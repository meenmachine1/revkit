// Objective-C without Foundation for the Mach-O tests (build.sh): a root
// class, a subclass with an ivar, a property and a protocol, and a category.
__attribute__((objc_root_class))
@interface Base {
  Class isa;
}
+ (id)alloc;
- (int)value;
@end
@implementation Base
+ (id)alloc { return (id)0; }
- (int)value { return 1; }
@end
@protocol Named
- (const char *)name;
@end
@interface Point : Base <Named> {
  int y;
}
@property int x;
- (int)sum;
@end
@implementation Point
- (int)sum { return self.x + y; }
- (const char *)name { return "point"; }
@end
@interface Point (Extra)
- (int)diff;
@end
@implementation Point (Extra)
- (int)diff { return self.x - y; }
@end
int main(void) {
  Point *p = [Point alloc];
  return [p sum] + [p diff];
}
