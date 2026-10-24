// The share extension's executable (build.sh): it links Greeter.framework
// from the app's Frameworks by @rpath, as Xcode's extensions do.
__attribute__((objc_root_class))
@interface UIResponder {
  Class isa;
}
@end
@interface UIViewController : UIResponder
@end
extern int greet(int);
@interface ShareViewController : UIViewController
- (void)post:(id)sender;
@end
@implementation ShareViewController
- (void)post:(id)sender { greet(7); }
@end
int main(void) { return greet(1); }
