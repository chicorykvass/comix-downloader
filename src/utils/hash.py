"""
Utility to generate Comix.to API hashes.
Ported from TypeScript implementation.
"""

import base64
import urllib.parse
from typing import List


class ComixHash:
    """Hash generator for Comix.to API requests."""

    KEYS = [
        "13YDu67uDgFczo3DnuTIURqas4lfMEPADY6Jaeqky+w=", "yEy7wBfBc+gsYPiQL/4Dfd0pIBZFzMwrtlRQGwMXy3Q=", "yrP+EVA1Dw==",
        "vZ23RT7pbSlxwiygkHd1dhToIku8SNHPC6V36L4cnwM=", "QX0sLahOByWLcWGnv6l98vQudWqdRI3DOXBdit9bxCE=", "WJwgqCmf",
        "BkWI8feqSlDZKMq6awfzWlUypl88nz65KVRmpH0RWIc=", "v7EIpiQQjd2BGuJzMbBA0qPWDSS+wTJRQ7uGzZ6rJKs=", "1SUReYlCRA==",
        "RougjiFHkSKs20DZ6BWXiWwQUGZXtseZIyQWKz5eG34=", "LL97cwoDoG5cw8QmhI+KSWzfW+8VehIh+inTxnVJ2ps=", "52iDqjzlqe8=",
        "U9LRYFL2zXU4TtALIYDj+lCATRk/EJtH7/y7qYYNlh8=", "e/GtffFDTvnw7LBRixAD+iGixjqTq9kIZ1m0Hj+s6fY=", "xb2XwHNB"
    ]

    @staticmethod
    def encoded_keys() -> List[bytes]:
        """Decode all keys from Base64."""
        return [base64.b64decode(k) for k in ComixHash.KEYS]

    @staticmethod
    def rc4(key: bytes, data: bytes) -> bytearray:
        """Standard RC4 encryption."""
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) & 0xff
            s[i], s[j] = s[j], s[i]
        
        i = 0
        j = 0
        out = bytearray()
        for k in range(len(data)):
            i = (i + 1) & 0xff
            j = (j + s[i]) & 0xff
            s[i], s[j] = s[j], s[i]
            rnd = s[(s[i] + s[j]) & 0xff]
            out.append(data[k] ^ rnd)
        return out

    # Mutation functions
    @staticmethod
    def mut_s(e: int) -> int: return (e + 143) & 0xff
    @staticmethod
    def mut_l(e: int) -> int: return ((e >> 1) | (e << 7)) & 0xff
    @staticmethod
    def mut_c(e: int) -> int: return (e + 115) & 0xff
    @staticmethod
    def mut_m(e: int) -> int: return (e ^ 177) & 0xff
    @staticmethod
    def mut_f(e: int) -> int: return (e - 188) & 0xff
    @staticmethod
    def mut_g(e: int) -> int: return ((e << 2) | (e >> 6)) & 0xff
    @staticmethod
    def mut_h(e: int) -> int: return (e - 42) & 0xff
    @staticmethod
    def mut_dollar(e: int) -> int: return ((e << 4) | (e >> 4)) & 0xff
    @staticmethod
    def mut_b(e: int) -> int: return (e - 12) & 0xff
    @staticmethod
    def mut_underscore(e: int) -> int: return (e - 20) & 0xff
    @staticmethod
    def mut_y(e: int) -> int: return ((e >> 1) | (e << 7)) & 0xff
    @staticmethod
    def mut_k(e: int) -> int: return (e - 241) & 0xff

    @staticmethod
    def get_mut_key(mk: bytes, idx: int) -> int:
        return mk[idx % 32] if (len(mk) > 0 and idx % 32 < len(mk)) else 0

    @classmethod
    def round1(cls, data: bytes, keys: List[bytes]) -> bytearray:
        enc = cls.rc4(keys[0], data)
        mut_key = keys[1]
        pref_key = keys[2]
        out = bytearray()

        for i in range(len(enc)):
            if i < 7 and i < len(pref_key):
                out.append(pref_key[i])
            v = enc[i] ^ cls.get_mut_key(mut_key, i)
            
            m = i % 10
            if m == 0 or m == 9: v = cls.mut_c(v)
            elif m == 1: v = cls.mut_b(v)
            elif m == 2: v = cls.mut_y(v)
            elif m == 3: v = cls.mut_dollar(v)
            elif m == 4 or m == 6: v = cls.mut_h(v)
            elif m == 5: v = cls.mut_s(v)
            elif m == 7: v = cls.mut_k(v)
            elif m == 8: v = cls.mut_l(v)
            out.append(v & 0xff)
        return out

    @classmethod
    def round2(cls, data: bytes, keys: List[bytes]) -> bytearray:
        enc = cls.rc4(keys[3], data)
        mut_key = keys[4]
        pref_key = keys[5]
        out = bytearray()

        for i in range(len(enc)):
            if i < 6 and i < len(pref_key):
                out.append(pref_key[i])
            v = enc[i] ^ cls.get_mut_key(mut_key, i)
            
            m = i % 10
            if m == 0 or m == 8: v = cls.mut_c(v)
            elif m == 1: v = cls.mut_b(v)
            elif m == 2 or m == 6: v = cls.mut_dollar(v)
            elif m == 3: v = cls.mut_h(v)
            elif m == 4 or m == 9: v = cls.mut_s(v)
            elif m == 5: v = cls.mut_k(v)
            elif m == 7: v = cls.mut_underscore(v)
            out.append(v & 0xff)
        return out

    @classmethod
    def round3(cls, data: bytes, keys: List[bytes]) -> bytearray:
        enc = cls.rc4(keys[6], data)
        mut_key = keys[7]
        pref_key = keys[8]
        out = bytearray()

        for i in range(len(enc)):
            if i < 7 and i < len(pref_key):
                out.append(pref_key[i])
            v = enc[i] ^ cls.get_mut_key(mut_key, i)
            
            m = i % 10
            if m == 0: v = cls.mut_c(v)
            elif m == 1: v = cls.mut_f(v)
            elif m == 2 or m == 8: v = cls.mut_s(v)
            elif m == 3: v = cls.mut_g(v)
            elif m == 4: v = cls.mut_y(v)
            elif m == 5: v = cls.mut_m(v)
            elif m == 6: v = cls.mut_dollar(v)
            elif m == 7: v = cls.mut_k(v)
            elif m == 9: v = cls.mut_b(v)
            out.append(v & 0xff)
        return out

    @classmethod
    def round4(cls, data: bytes, keys: List[bytes]) -> bytearray:
        enc = cls.rc4(keys[9], data)
        mut_key = keys[10]
        pref_key = keys[11]
        out = bytearray()

        for i in range(len(enc)):
            if i < 8 and i < len(pref_key):
                out.append(pref_key[i])
            v = enc[i] ^ cls.get_mut_key(mut_key, i)
            
            m = i % 10
            if m == 0: v = cls.mut_b(v)
            elif m == 1 or m == 9: v = cls.mut_m(v)
            elif m == 2 or m == 7: v = cls.mut_l(v)
            elif m == 3 or m == 5: v = cls.mut_s(v)
            elif m == 4 or m == 6: v = cls.mut_underscore(v)
            elif m == 8: v = cls.mut_y(v)
            out.append(v & 0xff)
        return out

    @classmethod
    def round5(cls, data: bytes, keys: List[bytes]) -> bytearray:
        enc = cls.rc4(keys[12], data)
        mut_key = keys[13]
        pref_key = keys[14]
        out = bytearray()

        for i in range(len(enc)):
            if i < 6 and i < len(pref_key):
                out.append(pref_key[i])
            v = enc[i] ^ cls.get_mut_key(mut_key, i)
            
            m = i % 10
            if m == 0: v = cls.mut_underscore(v)
            elif m == 1 or m == 7: v = cls.mut_s(v)
            elif m == 2: v = cls.mut_c(v)
            elif m == 3 or m == 5: v = cls.mut_m(v)
            elif m == 4: v = cls.mut_b(v)
            elif m == 6: v = cls.mut_f(v)
            elif m == 8: v = cls.mut_dollar(v)
            elif m == 9: v = cls.mut_g(v)
            out.append(v & 0xff)
        return out

    @classmethod
    def generate_hash(cls, path: str, body_size: int = 0, time: int = 1) -> str:
        """Generate the Comix hash for a given request path and time."""
        base_string = f"{path}:{body_size}:{time}"
        # JS encodeURIComponent equivalent in Python
        encoded = urllib.parse.quote(base_string, safe="-_.!~*'()")
        initial_bytes = encoded.encode('utf-8')
        
        keys = cls.encoded_keys()
        
        res1 = cls.round1(initial_bytes, keys)
        res2 = cls.round2(res1, keys)
        res3 = cls.round3(res2, keys)
        res4 = cls.round4(res3, keys)
        res5 = cls.round5(res4, keys)
        
        # JS GetURLBase64FromBytes equivalent
        return base64.urlsafe_b64encode(res5).decode('ascii').rstrip('=')


def generate_comix_hash(path: str, body_size: int = 0, time: int = 1) -> str:
    """Convenience function to generate the Comix hash."""
    return ComixHash.generate_hash(path, body_size, time)
