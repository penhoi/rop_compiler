#ifndef __CLASSIFIER__H_
#define __CLASSIFIER__H_

#include <cppgdsl/gdsl.h>
#include <cppgdsl/frontend/bare_frontend.h>

class Gadget; //Forward Declaration

class Classifier
{
  private:
    gdsl::gdsl * g;
    gdsl::bare_frontend * f;

  public:
    Classifier(std::string architecture);
    ~Classifier();

    std::vector<Gadget *> create_gadgets_from_instructions(unsigned char * bytes, unsigned long size, unsigned long long address);
};

#endif // __CLASSIFIER__H_
