// The fixture's C++ entry (shapes.h, kit.h).
#include "shapes.h"

#include "kit.h"

extern "C" int cxx_main(int seed) {
  Scene *scene = new Scene();
  scene->add(new Rect(1, 3, seed & 7));
  scene->add(new Circle(2, seed & 3));
  scene->add(new Rect(3, 2, 2));
  scene->move_all(1, -1);
  scene->scale_all(2);
  Shape *s = scene->find(2);
  int r = scene->total_area() + (s ? s->x + s->area() : 0);
  delete s;
  return r + scene->frames;
}
