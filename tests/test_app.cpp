#include <windows.h>
#include <stdio.h>

void hello(int n)
{
	fprintf(stdout, "hello world: %d\n", n);
}

void excpt()
{
	fprintf(stdout, "some exception\n");
}

int main()
{
  try {
    int i = 0;
    int j = 1 / i;
    hello(j);
  } catch(...) {
    excpt();
  }
  return 0;
}
