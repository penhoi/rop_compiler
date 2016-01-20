
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

#define BAD_INST_TYPE 0
#define CONTINUE      1
#define BRANCH_FOUND  2
#define EXPRESSION    3

class gadget_visitor : public visitor {
  public:
    std::map<id *, expr *> effects;
    int ret;
    expr * ret_expr;

    void visit(arbitrary *a) {
      printf("SEXPR_ARBITRARY %s\n", a->to_string().c_str());
    }

    void visit(sexpr_cmp *sc) {
      printf("SEXPR_CMP %s\n", sc->to_string().c_str());
    }

    void visit(sexpr_lin *sl) {
      printf("SEXPR_LIN %s\n", sl->to_string().c_str());
    }

    void _default(sexpr *s) {
      printf("DEFAULT_SEXPR %s\n", s->to_string().c_str());
    }

    void visit(expr_binop *eb) {
      printf("EXPR_BINOP: %s\n", eb->to_string().c_str());
    }

    void visit(expr_ext *ee) {
      printf("EXPR_EXT: %s\n", ee->to_string().c_str());
    }

    void visit(expr_sexpr *es) {
      sexpr * s = es->get_inner();
      printf("EXPR_SEXPR: %s, inner %s\n", es->to_string().c_str(), s->to_string().c_str());
      s->accept(*this);
    }


    void visit(assign *s) {
      variable * lhs = s->get_lhs();
      expr * rhs = s->get_rhs();
      printf("Assign: Variable %s Id %s Size %lld Offset %lld Rhs %s\n", lhs->to_string().c_str(),
        lhs->get_id()->to_string().c_str(), s->get_size(), lhs->get_offset(), rhs->to_string().c_str());

      rhs->accept(*this);
      ret = CONTINUE;
    }

    void visit(load *s) {
      variable * lhs = s->get_lhs();
      printf("Load: Variable %s Id %s Size %lld Offset %lld\n", lhs->to_string().c_str(), lhs->get_id()->to_string().c_str(), s->get_size(), lhs->get_offset());
      ret = CONTINUE;
    }

    void visit(store *s) {
      printf("store:\n");
      ret = CONTINUE;
    }

    void visit(branch *s) {
      address * a = s->get_target();
      printf("branch: %s\n", a->to_string().c_str());
      a->accept(*this);
      ret = BRANCH_FOUND;
    }

    void _default() {
      printf("Default\n");
      ret = BAD_INST_TYPE;
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
  int ret = CONTINUE;
  std::vector<Gadget *> gadgets;
  statements_t * rreil;

  g->set_code(bytes, size, address);

  gadget_visitor visitor;
  while(ret == CONTINUE) {
    try
    {
      gdsl::instruction insn = g->decode();
      rreil = insn.translate();

      printf("Instruction: %s\n", insn.to_string().c_str());
    } catch(gdsl::gdsl_exception) {
      ret = BAD_INST_TYPE; //Manually set the visitor's return type
      break;
    }

    for(statement *s : *rreil)
    {
      printf("%s\n", s->to_string().c_str());
      s->accept(visitor);
      printf("\n");
    }
    ret = visitor.ret;

    printf("Effects:\n");
    for (std::map<id *, expr *>::iterator it = visitor.effects.begin(); it != visitor.effects.end(); it++)
    {
      printf("%s <== %s\n", it->first->to_string().c_str(), it->second->to_string().c_str());
    }
    printf("\n");
  }

  if(ret == BRANCH_FOUND)
  {
    printf("Found gadget at %llx\n", address);
  }

  return gadgets;
}

