"""
Comix.to API wrapper for manga information and chapter data.
"""

from typing import Optional
from ..core.models import MangaInfo, Chapter
from ..utils.retry import retry_with_backoff
from ..utils.logger import get_logger
from ..utils.session import get_session
from ..utils.hash import generate_comix_hash

logger = get_logger(__name__)


class ComixAPI:
    """API wrapper for comix.to"""
    
    BASE_URL = "https://comix.to/api/v2"
    
    @staticmethod
    def extract_manga_code(url: str) -> str:
        """
        Extract manga code from the title URL.
        Example: https://comix.to/title/93q1r-the-summoner -> 93q1r
        """
        parts = url.rstrip("/").split("/")
        last = parts[-1] if parts[-1] else parts[-2]
        code = last.split("-")[0]
        logger.debug(f"Extracted manga code: {code} from URL: {url}")
        return code
    
    @classmethod
    @retry_with_backoff()
    def get_manga_info(cls, manga_code: str) -> Optional[MangaInfo]:
        """Fetch manga information from API."""
        url = f"{cls.BASE_URL}/manga/{manga_code}/"
        logger.debug(f"Fetching manga info from: {url}")
        
        response = get_session().get(url, timeout=30)
        response.raise_for_status()
        
        json_data = response.json()
        data = json_data.get("result")
        
        if not data:
            logger.error(f"API returned no result for manga code: {manga_code}. Response: {json_data}")
            return None
            
        return MangaInfo(
            manga_id=data.get("manga_id"),
            hash_id=data.get("hash_id"),
            title=data.get("title", "Unknown"),
            alt_titles=data.get("alt_titles", []),
            slug=data.get("slug"),
            rank=data.get("rank"),
            manga_type=data.get("type"),
            poster_url=data.get("poster", {}).get("large") or data.get("poster", {}).get("medium"),
            original_language=data.get("original_language"),
            status=data.get("status"),
            final_chapter=data.get("final_chapter"),
            latest_chapter=data.get("latest_chapter"),
            start_date=data.get("start_date"),
            end_date=data.get("end_date"),
            rated_avg=data.get("rated_avg"),
            rated_count=data.get("rated_count"),
            follows_total=data.get("follows_total"),
            is_nsfw=data.get("is_nsfw", False),
            year=data.get("year"),
            genres=data.get("term_ids", []),
            description=data.get("synopsis", "")
        )
    
    @classmethod
    def _fetch_chapter_page(cls, manga_code: str, page: int, force_flare: bool = False) -> tuple[int, list[dict]]:
        """Fetch a single page of chapters. Returns (page_number, items)."""
        base_path = f"/manga/{manga_code}/chapters"
        time_val = 1
        
        try:
            # Generate the required Comix hash for the request
            request_hash = generate_comix_hash(base_path, time=time_val)
            
            # API uses limit, page, order, time, and _ (hash)
            url = f"{cls.BASE_URL}{base_path}?limit=100&page={page}&order[number]=desc&time={time_val}&_={request_hash}"
            
            # If it's the first page and we aren't sure about the session, we can force flare
            response = get_session().get(url, timeout=30, force_flare=force_flare)
            response.raise_for_status()
            
            json_data = response.json()
            data = json_data.get("result")
            
            if data is None:
                # If result is null but status is 200, it might be a soft block or actual end
                # If it's page 1, it's very likely a block if no chapters are found
                if page == 1 and not force_flare:
                    logger.warning(f"Page 1 returned null result (even with hash). Retrying with forced FlareSolverr...")
                    return cls._fetch_chapter_page(manga_code, page, force_flare=True)
                    
                logger.debug(f"API returned null result for page {page} - possibly end of list.")
                return page, []
                
            return page, data.get("items", [])
        except Exception as e:
            # If we hit an error on page 1, try one last time with force_flare
            if page == 1 and not force_flare:
                logger.warning(f"Error fetching page 1: {e}. Retrying with forced FlareSolverr...")
                return cls._fetch_chapter_page(manga_code, page, force_flare=True)
                
            logger.warning(f"Failed to fetch page {page}: {str(e)}")
            return page, []
    
    @classmethod
    def get_all_chapters(cls, manga_code: str) -> list[Chapter]:
        """Fetch all chapters for a manga using parallel requests."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        all_items = {}  # page -> items mapping
        page_batch_size = 10  # Fetch 10 pages concurrently
        current_batch_start = 1
        found_empty = False
        
        logger.debug(f"Starting parallel chapter fetch for {manga_code}")
        
        while not found_empty:
            # Fetch a batch of pages in parallel
            pages_to_fetch = range(current_batch_start, current_batch_start + page_batch_size)
            
            with ThreadPoolExecutor(max_workers=page_batch_size) as executor:
                futures = {
                    executor.submit(cls._fetch_chapter_page, manga_code, page): page 
                    for page in pages_to_fetch
                }
                
                for future in as_completed(futures):
                    page_num, items = future.result()
                    if items:
                        all_items[page_num] = items
                    else:
                        found_empty = True
            
            current_batch_start += page_batch_size
        
        # Build chapters list in correct order
        chapters = []
        for page_num in sorted(all_items.keys()):
            for chap in all_items[page_num]:
                if not chap:
                    continue
                    
                group = chap.get("scanlation_group")
                is_official = chap.get("is_official", 0)
                
                # Determine group name: prefer scanlation_group, then check is_official
                if group:
                    group_name = group.get("name")
                elif is_official:
                    group_name = "Official"
                else:
                    group_name = None
                
                chapters.append(Chapter(
                    chapter_id=chap["chapter_id"],
                    number=chap["number"],
                    title=chap.get("name") or chap.get("title"),  # API uses 'name' field
                    volume=chap.get("volume"),
                    votes=chap.get("votes"),
                    group_name=group_name,
                    pages_count=chap.get("pages_count", 0)
                ))
        # Reverse the list so old chapters (low numbers) are at the beginning
        chapters.reverse()
        
        logger.info(f"Found {len(chapters)} chapters (fetched {len(all_items)} pages in parallel)")
        return chapters
    
    @classmethod
    @retry_with_backoff()
    def get_chapter_images(cls, chapter_id: int) -> list[str]:
        """Fetch all image URLs for a chapter."""
        base_path = f"/chapters/{chapter_id}/"
        time_val = 1
        
        request_hash = generate_comix_hash(base_path, time=time_val)
        url = f"{cls.BASE_URL}{base_path}?time={time_val}&_={request_hash}"
        
        logger.debug(f"Fetching images for chapter {chapter_id} (hash used)")
        
        response = get_session().get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        images = (data.get("result") or {}).get("images", [])
        image_urls = [img["url"] for img in images if "url" in img]
        
        logger.debug(f"Found {len(image_urls)} images")
        return image_urls
