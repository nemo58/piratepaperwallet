#include <iostream>
#include <cstring>

#include "arrrpaperrust.h"

using namespace std;

int main() {
  char * from_rust = rust_generate_wallet(1, "user-provided-entropy");
  auto stri = string(from_rust);
  cout << stri << endl;
  rust_free_string(from_rust);

  return 0;
}