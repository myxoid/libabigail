enum A {
  Ae = 1ull << 48,
};

enum B {
  Be = (1ull << 31) + 1,
};

unsigned int fun(enum A a, enum B b) {
  return sizeof(a) + sizeof(b);
}
