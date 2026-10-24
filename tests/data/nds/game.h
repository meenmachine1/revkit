// A tiny stand-in for a DS game's C++ (docs/nds.md, "Test fixtures"):
// classes with virtual methods, a constructor that stores the vtable, a
// Thumb function, soft float through the runtime's named helpers (as
// CodeWarrior's _fmul and _s32_div_f), main code an overlay calls into,
// and ITCM code. Built by make_fixture.py with clang for ARMv5TE; nothing
// here comes from a game.
#pragma once

extern "C" {
float _fadd(float a, float b);
float _fsub(float a, float b);
float _fmul(float a, float b);
float _fdiv(float a, float b);
int _s32_div_f(int a, int b);
int ItcmMix(int a, int b);
}

struct Vec2 {
  int x, y;
};

class SceneBase {
 public:
  SceneBase();
  virtual ~SceneBase();
  virtual void Update();
  virtual void Draw(int layer);
  int frame;
  int flags;
};

class GameOverScene : public SceneBase {
 public:
  GameOverScene();
  ~GameOverScene() override;
  void Update() override;
  void Draw(int layer) override;
  void ShowRetryWindow(int choice);
  Vec2 cursor;
  float fade;
};

int Clamp(int v, int lo, int hi);
int ThumbChecksum(const unsigned char *p, int n);
float Lerp(float a, float b, float t);
extern int gFrameCount;
extern SceneBase *gScene;
extern const int kRetryItems[4];
extern int gDtcmTable[4];

inline void *operator new(unsigned int, void *p) noexcept { return p; }
