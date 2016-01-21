#include <string.h>
#include <stdint.h>
#include <ctype.h>

void* memcpy(void* dest, const void* src, size_t len)
{
  if ((((uintptr_t)dest | (uintptr_t)src | len) & (sizeof(uintptr_t)-1)) == 0) {
    const uintptr_t* s = src;
    uintptr_t *d = dest;
    while (d < (uintptr_t*)(dest + len))
      *d++ = *s++;
  } else {
    const char* s = src;
    char *d = dest;
    while (d < (char*)(dest + len))
      *d++ = *s++;
  }
  return dest;
}

void* memset(void* dest, int byte, size_t len)
{
  if ((((uintptr_t)dest | len) & (sizeof(uintptr_t)-1)) == 0) {
    uintptr_t word = byte & 0xFF;
    word |= word << 8;
    word |= word << 16;
    word |= word << 16 << 16;

    uintptr_t *d = dest;
    while (d < (uintptr_t*)(dest + len))
      *d++ = word;
  } else {
    char *d = dest;
    while (d < (char*)(dest + len))
      *d++ = byte;
  }
  return dest;
}

int memcmp(const void *s1, const void *s2, size_t n)
{
  const unsigned long *longp1 = (const unsigned long *)s1;
  const unsigned long *longp2 = (const unsigned long *)s2;
  const unsigned char *str1 = (const unsigned char *)s1;
  const unsigned char *str2 = (const unsigned char *)s2;
  while (n > 8) {
    unsigned long c1 = *longp1++;
    unsigned long c2 = *longp2++;
    if (c1 < c2)
      return -1;
    if (c1 > c2)
      return 1;
    n -= 8;
  }
  while (n > 0) {
    unsigned char c1 = *str1++;
    unsigned char c2 = *str2++;
    if (c1 < c2)
      return -1;
    if (c1 > c2)
      return 1;
    n--;
  }
  return 0;
}

size_t strlen(const char *s)
{
  const char *p = s;
  while (*p)
    p++;
  return p - s;
}

int strcmp(const char* s1, const char* s2)
{
  unsigned char c1, c2;

  do {
    c1 = *s1++;
    c2 = *s2++;
  } while (c1 != 0 && c1 == c2);

  return c1 - c2;
}

char* strcpy(char* dest, const char* src)
{
  char* d = dest;
  while ((*d++ = *src++))
    ;
  return dest;
}

long atol(const char* str)
{
  long res = 0;
  int sign = 0;

  while (*str == ' ')
    str++;

  if (*str == '-' || *str == '+') {
    sign = *str == '-';
    str++;
  }

  while (*str) {
    res *= 10;
    res += *str++ - '0';
  }

  return sign ? -res : res;
}

long strtoul(const char* str, char **endptr, int base)
{
  long res = 0;
  int sign = 0;

  while (*str == ' ')
    str++;

  if (*str == '-' || *str == '+') {
    sign = *str == '-';
    str++;
  }

  if (*str == '0') {
    str++;
    if (*str == 'x') {
      base = 16;
      str++;
    } else if (*str == '0') {
      base = 8;
      str++;
    }
  }

  while (*str) {
    char c = *str++;
    res *= base;
    if ('0' <= c && c <= '9')
      res += c - '0';
    else if (base > 10 && 'A' <= c && c <= 'Z')
      res += c - 'A' + 10;
    else if (base > 10 && 'a' <= c && c <= 'z')
      res += c - 'a' + 10;
    else
      break;
  }

  if (endptr)
    *endptr = (char *)str;

  return sign ? -res : res;
}
