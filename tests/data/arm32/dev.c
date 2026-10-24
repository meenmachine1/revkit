// Devices (kit.h), ARM code.
#include "kit.h"

int dev_init(struct dev *d, int id, const char *name, dev_handler h) {
  int s = OS_DisableInterrupts();
  d->id = id;
  d->flags = 1;
  d->name = name;
  d->handler = h;
  d->count = 0;
  d->state = 0;
  d->next = 0;
  OS_RestoreInterrupts(s);
  return (int)kit_strlen(name);
}

int dev_dispatch(struct dev *d, int arg) {
  if (d->handler == 0 || (d->flags & 1) == 0) return -1;
  d->count++;
  return d->handler(d, arg);
}

void dev_touch(struct dev *d) {
  int s = OS_DisableInterrupts();
  d->count++;
  d->state = (u8)(d->state + 1);
  OS_RestoreInterrupts(s);
}

struct dev *dev_find(struct dev *list, int id) {
  for (; list; list = list->next)
    if (list->id == id) return list;
  return 0;
}

int dev_count_all(struct dev *list) {
  int n = 0;
  int s = OS_DisableInterrupts();
  for (; list; list = list->next) n += list->count;
  OS_RestoreInterrupts(s);
  return n;
}

