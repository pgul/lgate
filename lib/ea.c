/*
 * $Id$
 *
 * $Log$
 * Revision 2.1  2004/07/20 17:50:59  gul
 * \r\n -> \n
 *
 * Revision 2.0  2001/01/10 20:42:22  gul
 * We are under CVS for now
 *
 */
#ifdef  HAVE_ALLOC_H
#include <alloc.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <string.h>
#include <errno.h>
#define INCL_DOSFILEMGR
#define INCL_DOSERRORS
#include <os2.h>

#define _EA_ALIGN(i)     (((i) + 3) & -4)
#define _EA_SIZE1(n, v)  _EA_ALIGN (sizeof (FEA2) + (n) + (v))
#define _EA_SIZE2(p)     _EA_SIZE1 ((p)->cbName, (p)->cbValue)
#define _EAD_MERGE       0x0001

void debug(int level,char * format,...);

struct _ea
{
  int flags;
  int size;
  void *value;
};

struct _ead_data
{
  int count;                    /* Number of EAs */
  int max_count;                /* Number of pointers allocated for INDEX */
  int total_value_size;         /* Total size of values */
  int total_name_len;           /* Total length of names w/o null characters */
  size_t buffer_size;           /* Number of bytes allocated for BUFFER */
  PFEA2LIST buffer;             /* Buffer holding FEA2LIST */
  PFEA2 *index;                 /* Index for BUFFER */
};

struct del_data
{
  int fea_alloc;
  int fea_used;
  ULONG *patch;
  PFEA2LIST fea_ptr;
};

typedef struct _ead_data *_ead;

_ead _ead_create (void)
{
  _ead p;

  p = malloc (sizeof (*p));
  if (p == NULL)
    {
      errno = ENOMEM;
      return NULL;
    }
  p->count = 0;
  p->max_count = 0;
  p->total_value_size = 0;
  p->total_name_len = 0;
  p->buffer_size = 0;
  p->index = NULL;
  p->buffer = NULL;
  return p;
}

void _ead_destroy (_ead ead)
{
  if (ead->buffer != NULL) free (ead->buffer);
  if (ead->index != NULL) free (ead->index);
  free (ead);
}

int _ead_find (_ead ead, const char *name)
{
  int i;

  for (i = 0; i < ead->count; ++i)
    if (strcmp (name, ead->index[i]->szName) == 0)
      return i+1;
  errno = ENOENT;
  return -1;
}

int _ead_size_buffer (struct _ead_data *ead, int new_size)
{
  if (new_size > ead->buffer_size)
    {
      ead->buffer_size = new_size;
      ead->buffer = realloc (ead->buffer, ead->buffer_size);
      if (ead->buffer == NULL)
        {
          ead->buffer_size = 0;
          ead->count = 0;
          errno = ENOMEM;
          return -1;
        }
    }
  return 0;
}

int _ead_make_index (struct _ead_data *ead, int new_count)
{
  int i;
  PFEA2 pfea;

  if (new_count > ead->max_count)
    {
      ead->max_count = new_count;
      ead->index = realloc (ead->index, ead->max_count * sizeof (*ead->index));
      if (ead->index == NULL)
        {
          ead->max_count = 0;
          ead->count = 0;
          errno = ENOMEM;
          return -1;
        }
    }
  pfea = &ead->buffer->list[0];
  for (i = 0; i < new_count; ++i)
    {
      ead->index[i] = (PFEA2)pfea;
      pfea = (PFEA2)((char *)pfea + pfea->oNextEntryOffset);
    }
  return 0;
}

int _ead_replace (_ead ead, int index, int flags, const void *value, int size)
{
  PFEA2 dst;
  int old_size, new_size, offset;

  if (index < 1 || index > ead->count)
    {
      errno = EINVAL;
      return -1;
    }
  dst = ead->index[index-1];
  new_size = _EA_SIZE1 (dst->cbName, size);
  old_size = _EA_SIZE2 (dst);
  offset = (char *)dst - (char *)ead->buffer;
  dst = NULL;
  if (new_size > old_size)
    {
      if (_ead_size_buffer (ead, ead->buffer_size - old_size + new_size) < 0)
        return -1;
    }
  dst = (PFEA2)((char *)ead->buffer + offset);
  if (new_size != old_size && index != ead->count)
    memmove ((char *)dst + new_size, (char *)dst + old_size,
             ead->buffer->cbList - (offset + old_size));
  dst->fEA = flags;
  dst->cbValue = size;
  dst->oNextEntryOffset = (index == ead->count ? 0 : new_size);
  ead->buffer->cbList += new_size - old_size;
  memcpy (dst->szName + dst->cbName + 1, value, size);
  return _ead_make_index (ead, ead->count);
}

int _ead_add (_ead ead, const char *name, int flags, const void *value,
              int size)
{
  int i, len, new_size, offset;
  PFEA2 dst, last;

  i = _ead_find (ead, name);
  if (i >= 1)
    {
      if (_ead_replace (ead, i, flags, value, size) < 0)
        return -1;
      return i;
    }
  len = strlen (name);
  new_size = _EA_SIZE1 (len, size);
  if (ead->count == 0)
    offset = sizeof (ULONG);
  else
    {
      offset = ead->buffer->cbList;
      last = ead->index[ead->count - 1];
      last->oNextEntryOffset = _EA_SIZE2 (last);
    }
  if (_ead_size_buffer (ead, offset + new_size) < 0)
    return -1;
  ead->buffer->cbList = offset + new_size;
  dst = (PFEA2)((char *)ead->buffer + offset);
  dst->oNextEntryOffset = 0;
  dst->fEA = flags;
  dst->cbName = len;
  dst->cbValue = size;
  memcpy (dst->szName, name, len + 1);
  memcpy (dst->szName + len + 1, value, size);
  if (_ead_make_index (ead, ead->count + 1) < 0)
    return -1;
  ++ead->count;
  return ead->count;
}

void _ea_set_errno (ULONG rc)
{
  switch (rc)
    {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
      errno = ENOENT;
      break;
    case ERROR_ACCESS_DENIED:
      errno = EACCES;
      break;
    case ERROR_NOT_ENOUGH_MEMORY:
      errno = ENOMEM;
      break;
    case ERROR_INVALID_HANDLE:
      errno = EBADF;
      break;
    case ERROR_FILENAME_EXCED_RANGE:
      errno = ENAMETOOLONG;
      break;
    default:
      errno = EINVAL;
      break;
    }
}

int _ead_enum (struct _ead_data *ead, char *path, int handle,
               int (*function)(struct _ead_data *ead, PDENA2 pdena, void *arg),
               void *arg)
{
  void *dena_buf;
  void *fileref;
  ULONG dena_buf_size, index, count, rc, reftype, hf, i;
  PDENA2 pdena;
  int expand_dena_buf;

  if (path != NULL)
    {
      reftype = ENUMEA_REFTYPE_PATH;
      fileref = path;
    }
  else
    {
      hf = handle;
      reftype = ENUMEA_REFTYPE_FHANDLE;
      fileref = &hf;
    }
  dena_buf_size = 0; dena_buf = NULL;
  expand_dena_buf = 1; index = 1;
  for (;;)
    {
      if (expand_dena_buf)
        {
          dena_buf_size += 0x20000; /* DosEnumAttribute is broken */
          dena_buf = realloc (dena_buf, dena_buf_size);
          if (dena_buf == NULL)
            {
              errno = ENOMEM;
              return -1;
            }
        }
      count = -1;
      rc = DosEnumAttribute (reftype, fileref, index,
                             dena_buf, dena_buf_size, &count,
                             ENUMEA_LEVEL_NO_VALUE);
      if (rc == ERROR_BUFFER_OVERFLOW)
        expand_dena_buf = 1;
      else if (rc != 0)
        {
          free (dena_buf);
          _ea_set_errno (rc);
          return -1;
        }
      else if (count == 0)
        break;
      else
        {
          expand_dena_buf = 0; pdena = dena_buf;
          for (i = 0; i < count; ++i)
            {
              if (function (ead, pdena, arg) < 0)
                {
                  free (dena_buf);
                  return -1;
                }
              pdena = (PDENA2)((char *)pdena + pdena->oNextEntryOffset);
            }
          index += count;
        }
    }
  free (dena_buf);
  return 0;
}

static int _ead_del (struct _ead_data *ead, PDENA2 pdena, void *arg)
{
  int add;
  PFEA2 pfea;
  struct del_data *p;

  if (_ead_find (ead, pdena->szName) < 0)
    {
      p = arg;
      add = _EA_SIZE1 (pdena->cbName, 0);
      if (p->fea_used + add > p->fea_alloc)
        {
          p->fea_alloc += 512;          /* increment must be > add */
          p->fea_ptr = realloc (p->fea_ptr, p->fea_alloc);
          if (p->fea_ptr == NULL)
            return -1;
        }
      pfea = (PFEA2)((char *)p->fea_ptr + p->fea_used);
      pfea->oNextEntryOffset = add;
      pfea->fEA = 0;
      pfea->cbName = pdena->cbName;
      pfea->cbValue = 0;        /* Delete! */
      memcpy (pfea->szName, pdena->szName, pdena->cbName + 1);
      p->patch = &pfea->oNextEntryOffset;
      p->fea_used += add;
    }
  return 0;
}

int _ea_write (char *path, int handle, PFEA2LIST src)
{
  ULONG rc;
  EAOP2 eaop;

  eaop.fpGEA2List = NULL;
  eaop.fpFEA2List = src;
  eaop.oError = 0;
  if (path != NULL)
    rc = DosSetPathInfo (path, 2, &eaop, sizeof (eaop), 0);
  else
    rc = DosSetFileInfo (handle, 2, &eaop, sizeof (eaop));
  if (rc != 0)
    {
      _ea_set_errno (rc);
      return -1;
    }
  return 0;
}

int _ead_write (_ead ead, char *path, int handle, int flags)
{
  if (!(flags & _EAD_MERGE))
    {
      struct del_data dd;

      dd.fea_used = sizeof (ULONG);
      dd.fea_alloc = 0;
      dd.fea_ptr = NULL;
      dd.patch = NULL;
      if (_ead_enum (ead, path, handle, _ead_del, &dd) < 0)
        {
          if (dd.fea_ptr != NULL)
            free (dd.fea_ptr);
          return -1;
        }
      if (dd.fea_ptr != NULL)
        {
          *dd.patch = 0;
          dd.fea_ptr->cbList = dd.fea_used;
          if (_ea_write (path, handle, dd.fea_ptr) < 0)
            {
              free (dd.fea_ptr);
              return -1;
            }
          free (dd.fea_ptr);
        }
    }
  if (ead->count != 0 && _ea_write (path, handle, ead->buffer) < 0)
    return -1;
  return 0;
}

void easet (char *path, const char *name, const char *value)
{
  int size;
  _ead ead;
  char *buf, *uname;

  debug(7,"easet: set EA %s \"%s\" for %s",name,value,path);
  uname = strdup (name);
  if (uname == NULL)
    return;
  strupr (uname);
  ead = _ead_create ();
  if (ead == NULL)
    return;
  size = strlen (value);
  buf = malloc (size + 4);
  if (buf == NULL)
    return;
  ((USHORT *)buf)[0] = EAT_ASCII;
  ((USHORT *)buf)[1] = size;
  memcpy (buf+4, value, size);
  if (_ead_add (ead, uname, 0, buf, size+4) < 0)
    return;
  _ead_write (ead, path, 0, _EAD_MERGE);
  free (buf); free (uname);
  _ead_destroy (ead);
}

static int _ea_get (struct _ea *dst, char *path, int handle,
                    char *name)
{
  const void *fileref;
  ULONG rc, reftype, hf;
  EAOP2 eaop;
  PGEA2LIST pgealist;
  PFEA2LIST pfealist;
  PGEA2 pgea;
  PFEA2 pfea;
  int len, size;

  dst->flags = 0;
  dst->size = 0;
  dst->value = NULL;
  if (path != NULL)
    {
      reftype = ENUMEA_REFTYPE_PATH;
      fileref = path;
    }
  else
    {
      hf = handle;
      reftype = ENUMEA_REFTYPE_FHANDLE;
      fileref = &hf;
    }
  len = strlen (name);
  size = sizeof (GEA2LIST) + len;
  pgealist = alloca (size);
  pgealist->cbList = size;
  pgea = &pgealist->list[0];
  pgea->oNextEntryOffset = 0;
  pgea->cbName = len;
  memcpy (pgea->szName, name, len + 1);
  size = sizeof (FEA2LIST) + 0x10000;
  pfealist = malloc (size);
  pfealist->cbList = size;
  eaop.fpGEA2List = pgealist;
  eaop.fpFEA2List = pfealist;
  eaop.oError = 0;
  if (path == NULL)
    rc = DosQueryFileInfo (handle, FIL_QUERYEASFROMLIST, &eaop,
                           sizeof (eaop));
  else
    rc = DosQueryPathInfo (path, FIL_QUERYEASFROMLIST, &eaop,
                           sizeof (eaop));
  if (rc != 0)
    {
      _ea_set_errno (rc);
      free(pfealist);
      return -1;
    }
  pfea = &pfealist->list[0];
  if (pfea->cbValue != 0)
    {
      dst->value = malloc (pfea->cbValue);
      if (dst->value == NULL)
        {
          errno = ENOMEM;
          free(pfealist);
          return -1;
        }
      memcpy (dst->value, pfea->szName + pfea->cbName + 1, pfea->cbValue);
    }
  dst->flags = pfea->fEA;
  dst->size = pfea->cbValue;
  free(pfealist);
  return 0;
}

char * get_ea (char *path, char *name)
{
  char *uname;
  struct _ea dst;
  int len;
  char * value;

  uname = strdup (name);
  if (uname == NULL)
    return NULL;
  strupr (uname);
  _ea_get (&dst, path, -1, uname);
  free(uname);
  if (dst.value == NULL) return NULL;
  if (*(USHORT*)dst.value!=EAT_ASCII)
  { free(dst.value);
    return NULL;
  }
  len=((USHORT*)dst.value)[1];
  value=malloc(len+1);
  if (value==NULL)
  { free(dst.value);
    return NULL;
  }
  memcpy(value, ((char*)dst.value)+4, len);
  free(dst.value);
  value[len]='\0';
  return value;
}
