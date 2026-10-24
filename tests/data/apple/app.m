// The demo app's main executable (build.sh), without an SDK: view
// controllers whose actions the storyboard and nibs make_bundle.py writes
// wire up. UIResponder and UIViewController (NSResponder and
// NSViewController for the macOS build) come from a hand-written UIKit.tbd
// (AppKit.tbd).
#ifdef DEMO_MAC
#define Responder_ NSResponder
#define Controller_ NSViewController
#else
#define Responder_ UIResponder
#define Controller_ UIViewController
#endif

__attribute__((objc_root_class))
@interface Responder_ {
  Class isa;
}
@end
@interface Controller_ : Responder_
@end

extern int greet(int);

@interface AppDelegate : Responder_
- (void)showAbout:(id)sender;
@end
@implementation AppDelegate
- (void)showAbout:(id)sender { greet(0); }
@end

@interface ViewController : Controller_ {
  int taps;
}
- (void)buttonTapped:(id)sender;
- (void)sliderChanged:(id)sender;
@end
@implementation ViewController
- (void)buttonTapped:(id)sender { taps = greet(taps); }
- (void)sliderChanged:(id)sender { taps = 0; }
@end

@interface SettingsController : Controller_
- (void)save:(id)sender;
- (void)cancel:(id)sender;
@end
@implementation SettingsController
- (void)save:(id)sender { greet(1); }
- (void)cancel:(id)sender { greet(2); }
@end

// copyAll: is implemented once, so a first-responder action resolves by it.
@interface TextResponder : Responder_
- (void)copyAll:(id)sender;
@end
@implementation TextResponder
- (void)copyAll:(id)sender { greet(3); }
@end

int main(void) { return greet(42); }
