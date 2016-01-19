
#include <cppgdsl/block.h>
#include <cppgdsl/frontend/bare_frontend.h>
#include <cppgdsl/frontend/frontend.h>
#include <cppgdsl/rreil/linear/lin_imm.h>
#include <cppgdsl/instruction.h>
#include <cppgdsl/rreil/statement/statement.h>
#include <cppgdsl/rreil_builder.h>
#include <cppgdsl/gdsl.h>
#include <cppgdsl/rreil/statement/load.h>
#include <cppgdsl/rreil/statement/branch.h>
#include <cppgdsl/rreil/visitor.h>
#include <cppgdsl/gdsl_exception.h>

#include <cppgdsl/optimization.h>
#include <cppgdsl/rreil/linear/lin_var.h>

#include <cppgdsl/rreil/linear/lin_binop.h>

#include <cppgdsl/rreil/statement/assign.h>
#include <cppgdsl/rreil/statement/statement_visitor.h>

#include <stdio.h>
#include <climits>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <map>
#include <vector>

#include "classifier.h"
#include "gadget.h"

using gdsl::block;

using namespace gdsl::rreil;

class gadget_visitor : public visitor {
  public:
    std::map<variable *, expr *> effects;

  void visit(expr_binop *a) {
    printf("EXPR_BINOP: %s\n", a->to_string().c_str());
  }

  void visit(expr_ext *a) {
    printf("EXPR_EXT: %s\n", a->to_string().c_str());
  }

  void visit(expr_sexpr *a) {
    printf("EXPR_SEXPR: %s\n", a->to_string().c_str());
  }


  void visit(assign *s) {
    variable * lhs = s->get_lhs();
    expr * rhs = s->get_rhs();
    printf("Assign: Variable %s Id %s Size %lld Offset %lld Rhs %s\n", lhs->to_string().c_str(),
      lhs->get_id()->to_string().c_str(), s->get_size(), lhs->get_offset(), rhs->to_string().c_str());

    rhs->accept(*this);
  }

  void visit(load *s) {
    variable * lhs = s->get_lhs();
    printf("Load: Variable %s Id %s Size %lld Offset %lld\n", lhs->to_string().c_str(), lhs->get_id()->to_string().c_str(), s->get_size(), lhs->get_offset());
  }

  void visit(store *s) {
    printf("store:\n");
  }

  void visit(branch *s) {
    address * a = s->get_target();
    printf("branch: %s\n", a->to_string().c_str());
    a->accept(*this);
  }

  void _default() {
    printf("No assignment :-(\n");
  }
};

//////////////////////////////////////////////////////////////////////////////////////
// Classifier ////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////

Classifier::Classifier(std::string architecture)
{
  f = new gdsl::bare_frontend(architecture);
  g = new gdsl::gdsl(f);
}

Classifier::~Classifier()
{
  delete g;
  delete f;
}

std::vector<Gadget *> Classifier::create_gadgets_from_instructions(unsigned char * bytes,
  unsigned long size, unsigned long long address)
{
  std::vector<Gadget *> gadgets;
  statements_t * rreil;

  g->set_code(bytes, size, 0);

  gadget_visitor visitor;
  while(true) {
    try
    {
      gdsl::instruction insn = g->decode();
      rreil = insn.translate();

      printf("Instruction: %s\n", insn.to_string().c_str());
    } catch(gdsl::gdsl_exception) {
      break;
    }

    for(statement *s : *rreil)
    {
      printf("%s\n", s->to_string().c_str());
      s->accept(visitor);
      printf("\n");
    }

    printf("Effects:\n");
    for (std::map<variable *, expr *>::iterator it = visitor.effects.begin(); it != visitor.effects.end(); it++)
    {
      printf("%s <== %s\n", it->first->to_string().c_str(), it->second->to_string().c_str());
    }
    printf("\n");
  }

  return gadgets;
}

/*
struct example_visitor: public statement_visitor {
  void visit(assign *s) {
    printf("Size of assignment: %lld\n", s->get_size());
  }

  void _default() {
    printf("No assignment :-(\n");
  }
};

void demo_single(gdsl::gdsl &g) {
  uint16_t buffer = 0x0000;
  g.set_code((unsigned char*) &buffer, sizeof(buffer), 0);

  gdsl::instruction insn = g.decode();

  printf("Instruction: %s\n", insn.to_string().c_str());
  printf("---------------------------------\n");

  auto rreil = insn.translate();

  g.reset_heap();

  printf("RReil:\n");
  for(statement *s : *rreil)
    printf("%s\n", s->to_string().c_str());

  printf("\n---------------------------------\n");
  printf("Sizes of assignments:\n");
  for(statement *s : *rreil) {
    example_visitor v;
    s->accept(v);
  }
  printf("Sizes of assignments and loads:\n");
  for(statement *s : *rreil) {

    bool ip = false;
    int_t ip_offset;

    statement_visitor v;
    v._([&](assign *a) {
      visitor *ev = new visitor();
      ((linear_visitor*)ev)->_([&](lin_binop *a) {
            if(a->get_op() == BIN_LIN_ADD) {
              linear_visitor lv;
              lv._([&](lin_var *v) {
                if(v->get_var()->get_id()->to_string() == "IP") {
                  ip = true;
                }
              });
              a->get_opnd1()->accept(lv);
              lv._([&](lin_imm *i) {
                    ip_offset = i->get_imm();
                  });
              a->get_opnd2()->accept(lv);
            }
          });
      a->accept(*ev);
      printf("Size of assignment: %lld\n", a->get_size());

      delete ev;
    });

    v._([&](load *l) {
      printf("Size of load: %lld\n", l->get_size());
    });
    s->accept(v);

    if(ip) {
      printf("IP added offset: %llu\n", ip_offset);
    }
  }
  printf("Counting variables...\n");
  size_t vars = 0;
  for(statement *s : *rreil) {
    visitor *v = new visitor();
    ((statement_visitor*) v)->_([&](assign *a) {
      printf("Assignment\n");
    });

    v->_((std::function<void(variable*)>)([&](variable *a) {
      std::cout << (*a == *a ? "The variable equals itself" : ":-(") << std::endl;
      vars++;
      printf("Variable!\n");
    }));
    s->accept(*v);
    delete v;
  }
  printf("Number of variables: %zu\n", vars);

  // Cleanup
  for(statement *s : *rreil)
    delete s;
  delete rreil;
}
*/
