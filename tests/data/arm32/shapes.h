// The fixture's C++ (kit.h): classes with fields and virtual methods, a
// constructor storing the vtable, virtual calls through it. The header is
// also what a user imports (docs/types.md, "C++ classes as `this`").
#pragma once

class Shape {
 public:
  explicit Shape(int id);
  virtual ~Shape();
  virtual int area() const = 0;
  virtual void scale(int k);
  void move(int dx, int dy);
  int id;
  int x;
  int y;
  unsigned flags;
};

class Rect : public Shape {
 public:
  Rect(int id, int w, int h);
  int area() const override;
  void scale(int k) override;
  int w;
  int h;
};

class Circle : public Shape {
 public:
  Circle(int id, int r);
  int area() const override;
  void scale(int k) override;
  int r;
};

class Scene {
 public:
  Scene();
  bool add(Shape *s);
  int total_area() const;
  void move_all(int dx, int dy);
  void scale_all(int k);
  Shape *find(int id) const;
  Shape *items[8];
  int count;
  int frames;
};
