// The fixture's scene (shapes.h): virtual calls through each item.
#include "shapes.h"

Scene::Scene() : count(0), frames(0) {
  for (int i = 0; i < 8; i++) items[i] = nullptr;
}

bool Scene::add(Shape *s) {
  if (count >= 8) return false;
  items[count++] = s;
  return true;
}

int Scene::total_area() const {
  int a = 0;
  for (int i = 0; i < count; i++) a += items[i]->area();
  return a;
}

void Scene::move_all(int dx, int dy) {
  for (int i = 0; i < count; i++) items[i]->move(dx, dy);
  frames++;
}

void Scene::scale_all(int k) {
  for (int i = 0; i < count; i++) items[i]->scale(k);
}

Shape *Scene::find(int id) const {
  for (int i = 0; i < count; i++)
    if (items[i]->id == id) return items[i];
  return nullptr;
}

