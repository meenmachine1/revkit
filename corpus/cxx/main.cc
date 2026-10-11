// The demangler gate's executable: calls into libshapes, so its stripped
// build names the library's functions only through its imports.
#include <cstdio>
#include <string>
#include <vector>

namespace geo {
enum class Kind { circle, rect, poly };
class Shape {
 public:
  virtual ~Shape();
  virtual double area() const = 0;
  static Shape *make(Kind kind, double a, double b);
  static int count();
};
double total_area(const std::vector<Shape *> &shapes);
}  // namespace geo
namespace util {
class Registry {
 public:
  void put(const std::string &key, int value);
  int get(const std::string &key, int fallback) const;
  static Registry &global();
};
unsigned checksum(const std::string &s);
}  // namespace util
extern "C" int shapes_demo(int n);

int main(int argc, char **argv) {
  std::vector<geo::Shape *> shapes;
  for (int i = 1; i < argc; ++i) shapes.push_back(geo::Shape::make(static_cast<geo::Kind>(i % 3), i, i * 2));
  util::Registry::global().put(argc > 1 ? argv[1] : "none", geo::Shape::count());
  std::printf("%f %d %u %d\n", geo::total_area(shapes), util::Registry::global().get("none", -1),
              util::checksum(std::string(argv[0])), shapes_demo(argc));
  for (geo::Shape *s : shapes) delete s;
  return 0;
}
