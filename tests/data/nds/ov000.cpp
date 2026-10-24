#include "game.h"

GameOverScene::GameOverScene() : cursor{0, 0}, fade(1.0f) {}
GameOverScene::~GameOverScene() { gScene = nullptr; }

void GameOverScene::Update() {
  SceneBase::Update();
  fade = Lerp(fade, 0.0f, 0.25f);
  cursor.x = Clamp(cursor.x + 1, 0, kRetryItems[2]);
  if (frame > 60) ShowRetryWindow(_s32_div_f(frame, 3));
}

void GameOverScene::Draw(int layer) {
  SceneBase::Draw(layer);
  gFrameCount += ItcmMix(layer, cursor.y);
}

void GameOverScene::ShowRetryWindow(int choice) {
  cursor.y = Clamp(choice, 0, 3);
  fade = _fdiv(fade, 2.0f);
}

extern "C" SceneBase *CreateGameOver(void *memory) {
  gScene = new (memory) GameOverScene();
  return gScene;
}

// The DS's I/O (docs/nds.md, "Memory map"): waiting on the SDK's VBlank
// counter in main memory's shared area and on a scanline (VCOUNT), with
// interrupts off (IME saved and restored). Each read is the hardware's.
extern "C" int WaitFrames(int frames) {
  volatile unsigned short *const vcount = (volatile unsigned short *)0x04000006;
  volatile unsigned int *const vblanks = (volatile unsigned int *)0x027FFC3C;
  volatile unsigned short *const ime = (volatile unsigned short *)0x04000208;
  const unsigned short saved = *ime;
  *ime = 0;
  const unsigned int until = *vblanks + frames;
  while (*vblanks != until) {
  }
  while (*vcount != 192) {
  }
  *ime = saved;
  return saved;
}
