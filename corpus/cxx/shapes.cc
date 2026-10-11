// A C++ library for the demangler gate (docs/demangle.md): namespaces,
// classes, constructors and destructors, virtual, const and static member
// functions, overloads, operators, templates, references, function
// pointers, enums and the standard library, exported so a stripped build
// keeps their mangled names.
#include <algorithm>
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#define API __attribute__((visibility("default"), noinline))

namespace geo {

constexpr double kPi = 3.14159265358979323846;

enum class Kind { circle, rect, poly };
enum Flags { none = 0, filled = 1, outlined = 2 };

struct Point {
  double x = 0, y = 0;
};

class Shape {
 public:
  Shape(const char *name, Kind kind);
  virtual ~Shape();
  virtual double area() const = 0;
  virtual double perimeter() const = 0;
  virtual void scale(double factor);
  const char *name() const { return name_; }
  Kind kind() const { return kind_; }
  int id() const;
  void set_flags(int flags);
  bool has(Flags f) const;
  static int count();
  static Shape *make(Kind kind, double a, double b);

 protected:
  char name_[16];
  Kind kind_;
  int flags_ = 0;
  int id_;
  static int created_;
};

class Circle : public Shape {
 public:
  explicit Circle(double r);
  ~Circle() override;
  double area() const override;
  double perimeter() const override;
  void scale(double factor) override;
  double radius() const { return r_; }
  bool contains(const Point &p) const;
  bool contains(double x, double y) const;

 private:
  double r_;
};

class Rect : public Shape {
 public:
  Rect(double w, double h);
  double area() const override;
  double perimeter() const override;
  Rect &operator+=(const Rect &other);
  bool operator==(const Rect &other) const;
  double width() const;
  double height() const;
  void resize(double w, double h, bool keep_ratio);

 private:
  double w_, h_;
};

class Polygon : public Shape {
 public:
  Polygon();
  ~Polygon() override;
  void add(const Point &p);
  void add(double x, double y);
  std::size_t size() const;
  double area() const override;
  double perimeter() const override;
  const Point *at(std::size_t i) const;
  void for_each(void (*fn)(const Point &, void *), void *ctx) const;

 private:
  std::vector<Point> pts_;
};

int Shape::created_ = 0;

Shape::Shape(const char *name, Kind kind) : kind_(kind), id_(++created_) {
  std::strncpy(name_, name, sizeof name_ - 1);
  name_[sizeof name_ - 1] = 0;
}
Shape::~Shape() { std::printf("~%s %d\n", name_, id_); }
void Shape::scale(double factor) { flags_ |= factor > 1 ? filled : outlined; }
int Shape::id() const { return id_; }
void Shape::set_flags(int flags) { flags_ = flags; }
bool Shape::has(Flags f) const { return (flags_ & f) != 0; }
int Shape::count() { return created_; }

Circle::Circle(double r) : Shape("circle", Kind::circle), r_(r) {}
Circle::~Circle() { r_ = 0; }
double Circle::area() const { return kPi * r_ * r_; }
double Circle::perimeter() const { return 2 * kPi * r_; }
void Circle::scale(double factor) {
  r_ *= factor;
  Shape::scale(factor);
}
bool Circle::contains(const Point &p) const { return p.x * p.x + p.y * p.y <= r_ * r_; }
bool Circle::contains(double x, double y) const { return contains(Point{x, y}); }

Rect::Rect(double w, double h) : Shape("rect", Kind::rect), w_(w), h_(h) {}
double Rect::area() const { return w_ * h_; }
double Rect::perimeter() const { return 2 * (w_ + h_); }
Rect &Rect::operator+=(const Rect &other) {
  w_ += other.w_;
  h_ += other.h_;
  return *this;
}
bool Rect::operator==(const Rect &other) const { return w_ == other.w_ && h_ == other.h_; }
double Rect::width() const { return w_; }
double Rect::height() const { return h_; }
void Rect::resize(double w, double h, bool keep_ratio) {
  if (keep_ratio && w_ != 0) h = w * h_ / w_;
  w_ = w;
  h_ = h;
}

Polygon::Polygon() : Shape("polygon", Kind::poly) {}
Polygon::~Polygon() { pts_.clear(); }
void Polygon::add(const Point &p) { pts_.push_back(p); }
void Polygon::add(double x, double y) { pts_.push_back(Point{x, y}); }
std::size_t Polygon::size() const { return pts_.size(); }
double Polygon::area() const {
  double a = 0;
  for (std::size_t i = 0; i < pts_.size(); ++i) {
    const Point &p = pts_[i], &q = pts_[(i + 1) % pts_.size()];
    a += p.x * q.y - q.x * p.y;
  }
  return std::fabs(a) / 2;
}
double Polygon::perimeter() const {
  double s = 0;
  for (std::size_t i = 0; i < pts_.size(); ++i) {
    const Point &p = pts_[i], &q = pts_[(i + 1) % pts_.size()];
    s += std::hypot(q.x - p.x, q.y - p.y);
  }
  return s;
}
const Point *Polygon::at(std::size_t i) const { return i < pts_.size() ? &pts_[i] : nullptr; }
void Polygon::for_each(void (*fn)(const Point &, void *), void *ctx) const {
  for (const Point &p : pts_) fn(p, ctx);
}

Shape *Shape::make(Kind kind, double a, double b) {
  switch (kind) {
    case Kind::circle: return new Circle(a);
    case Kind::rect: return new Rect(a, b);
    case Kind::poly: {
      auto *p = new Polygon();
      p->add(0, 0);
      p->add(a, 0);
      p->add(a, b);
      return p;
    }
  }
  return nullptr;
}

API double total_area(const std::vector<Shape *> &shapes) {
  double t = 0;
  for (const Shape *s : shapes) t += s->area();
  return t;
}

API int count_kind(const std::vector<Shape *> &shapes, Kind kind) {
  return static_cast<int>(std::count_if(shapes.begin(), shapes.end(), [kind](const Shape *s) { return s->kind() == kind; }));
}

API Point centroid(const Point *pts, int n) {
  Point c;
  for (int i = 0; i < n; ++i) {
    c.x += pts[i].x;
    c.y += pts[i].y;
  }
  if (n > 0) {
    c.x /= n;
    c.y /= n;
  }
  return c;
}

API double distance(const Point &a, const Point &b) { return std::hypot(a.x - b.x, a.y - b.y); }

}  // namespace geo

namespace util {

template <typename T>
API T clamp(T v, T lo, T hi) {
  return v < lo ? lo : v > hi ? hi : v;
}
template int clamp<int>(int, int, int);
template double clamp<double>(double, double, double);
template long clamp<long>(long, long, long);

template <typename T>
class Stack {
 public:
  void push(const T &v) { items_.push_back(v); }
  bool pop(T *out) {
    if (items_.empty()) return false;
    *out = items_.back();
    items_.pop_back();
    return true;
  }
  std::size_t depth() const { return items_.size(); }

 private:
  std::vector<T> items_;
};
template class Stack<int>;
template class Stack<std::string>;

class Registry {
 public:
  void put(const std::string &key, int value);
  int get(const std::string &key, int fallback) const;
  bool remove(const char *key);
  std::size_t size() const;
  std::string describe(int limit) const;
  static Registry &global();

 private:
  std::map<std::string, int> map_;
};

void Registry::put(const std::string &key, int value) { map_[key] = value; }
int Registry::get(const std::string &key, int fallback) const {
  auto it = map_.find(key);
  return it == map_.end() ? fallback : it->second;
}
bool Registry::remove(const char *key) { return map_.erase(key) != 0; }
std::size_t Registry::size() const { return map_.size(); }
std::string Registry::describe(int limit) const {
  std::string out;
  for (const auto &[k, v] : map_) {
    if (limit-- <= 0) break;
    out += k + "=" + std::to_string(v) + ";";
  }
  return out;
}
Registry &Registry::global() {
  static Registry r;
  return r;
}

API std::uint32_t checksum(const unsigned char *data, std::size_t n, std::uint32_t seed) {
  std::uint32_t h = seed;
  for (std::size_t i = 0; i < n; ++i) h = (h ^ data[i]) * 16777619u;
  return h;
}
API std::uint32_t checksum(const std::string &s) { return checksum(reinterpret_cast<const unsigned char *>(s.data()), s.size(), 2166136261u); }
API int parse_int(const char *text, int base, bool *ok) {
  char *end = nullptr;
  long v = std::strtol(text, &end, base);
  if (ok) *ok = end != text && *end == 0;
  return static_cast<int>(v);
}
API void log_line(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
API void log_line(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  std::vfprintf(stderr, fmt, ap);
  va_end(ap);
}
API int apply(int (*fn)(int, int), int a, int b) { return fn(a, b); }
API short widen(signed char c, unsigned short s, long long w) { return static_cast<short>(c + s + w); }
API bool same(const char *a, const char *b, std::size_t n) { return std::strncmp(a, b, n) == 0; }

}  // namespace util

extern "C" API int shapes_demo(int n) {
  std::vector<geo::Shape *> shapes;
  for (int i = 0; i < n; ++i) shapes.push_back(geo::Shape::make(static_cast<geo::Kind>(i % 3), i + 1, i + 2));
  double t = geo::total_area(shapes);
  util::Registry::global().put("total", static_cast<int>(t));
  util::Stack<int> st;
  for (int i = 0; i < n; ++i) st.push(util::clamp(i, 1, 5));
  int v = 0, sum = 0;
  while (st.pop(&v)) sum += v;
  for (geo::Shape *s : shapes) delete s;
  return sum + geo::count_kind(shapes, geo::Kind::rect) + util::Registry::global().get("total", 0);
}
