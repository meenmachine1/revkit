// C++ fixture: namespaces, classes, references, member functions.
namespace geo {

struct Vec {
  double x, y;
  double dot(const Vec &o) const { return x * o.x + y * o.y; }
};

class Shape {
 public:
  explicit Shape(int sides) : sides_(sides) {}
  int sides() const { return sides_; }
  static Shape *make(int n);

 private:
  int sides_;
};

Shape *Shape::make(int n) { return new Shape(n); }

double length(const Vec &v, Vec &&w) { return v.dot(v) + w.x; }

}  // namespace geo

int main() {
  geo::Vec v{1, 2};
  geo::Shape *s = geo::Shape::make(3);
  int r = s->sides() + int(geo::length(v, geo::Vec{3, 4}));
  delete s;
  return r;
}
