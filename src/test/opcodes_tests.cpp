// Copyright (c) 2012-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <boost/test/unit_test.hpp>
#include <cassert>

using namespace std;

namespace {

typedef std::vector<uint8_t> valtype;
typedef std::vector<valtype> stacktype;

std::vector<uint32_t> flagset{0,
    STANDARD_SCRIPT_VERIFY_FLAGS,
    MANDATORY_SCRIPT_VERIFY_FLAGS};

static void CheckOpError(uint32_t flags, const stacktype& original_stack, const CScript& script, ScriptError expected_error)
{
    BaseSignatureChecker sigchecker;

    ScriptError err = SCRIPT_ERR_OK;
    stacktype stack{original_stack};
    bool r = EvalScript(stack, script, flags | SCRIPT_ENABLE_DIP0020_OPDCODES, sigchecker, SigVersion::BASE, &err);
    BOOST_CHECK(!r);
    BOOST_CHECK_EQUAL(err, expected_error);
}

static void CheckOpError(const stacktype& original_stack,
    const CScript& script,
    ScriptError expected_error)
{
    for (uint32_t flags : flagset) {
        CheckOpError(flags, original_stack, script, expected_error);
    }
}

static void CheckOpError(const valtype& a, const CScript& script, ScriptError expected_error)
{
    CheckOpError(stacktype{a}, script, expected_error);
}

static void CheckOpError(const valtype& a, const valtype& b, const CScript& script, ScriptError expected_error)
{
    CheckOpError(stacktype{a, b}, script, expected_error);
}

static void CheckOp(uint32_t flags, const stacktype original_stack, const CScript& script, const stacktype& expected_stack)
{
    BaseSignatureChecker sigchecker;

    ScriptError err = SCRIPT_ERR_OK;
    stacktype stack{original_stack};
    bool r = EvalScript(stack, script, flags| SCRIPT_ENABLE_DIP0020_OPDCODES, sigchecker, SigVersion::BASE, &err);
    BOOST_CHECK(r);
    BOOST_CHECK(stack == expected_stack);
}

static void CheckOp(const stacktype& original_stack, const CScript& script, const stacktype& expected_stack)
{
    for (uint32_t flags : flagset) {
        CheckOp(flags, original_stack, script, expected_stack);
    }
}

static void CheckOp(const stacktype& original_stack, const CScript& script, const valtype& expected)
{
    CheckOp(original_stack, script, stacktype{expected});
}

static void CheckOp(const valtype& a, const CScript& script, const valtype& expected)
{
    CheckOp(stacktype{a}, script, expected);
}

static void CheckOp(const valtype& a, const valtype& b, const CScript& script, const valtype& expected)
{
    CheckOp(stacktype{a, b}, script, expected);
}

} // namespace

void test_cat()
{
    CScript script;
    script << OP_CAT;

    // Two inputs required
    CheckOpError(stacktype(), script, SCRIPT_ERR_INVALID_STACK_OPERATION);
    CheckOpError(stacktype{{0x00}}, script, SCRIPT_ERR_INVALID_STACK_OPERATION);

    valtype maxlength_valtype(MAX_SCRIPT_ELEMENT_SIZE, 0x00);

    // Concatenation producing illegal sized output
    CheckOpError(stacktype{{maxlength_valtype}, {0x00}}, script, SCRIPT_ERR_PUSH_SIZE);

    // Concatenation of a max-sized valtype with empty is legal
    CheckOp(stacktype{{maxlength_valtype}, {}}, script, maxlength_valtype);
    CheckOp(stacktype{{}, {maxlength_valtype}}, script, maxlength_valtype);

    // Concatenation of a zero length operand
    CheckOp(stacktype{{0x01}, {}}, script, valtype{0x01});
    CheckOp(stacktype{{}, {0x01}}, script, valtype{0x01});

    // Concatenation of two empty operands results in empty valtype
    CheckOp(stacktype{{}, {}}, script, valtype{});

    // Concatenating two operands generates the correct result
    CheckOp(stacktype{{0x00}, {0x00}}, script, {0x00, 0x00});
    CheckOp(stacktype{{0x01}, {0x02}}, script, {0x01, 0x02});
    CheckOp(stacktype{{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
                {0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}},
        script,
        valtype{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14});
}

void test_split()
{
    CScript script;
    script << OP_SPLIT; //inputs: x n; outputs: x1 x2

    // Two inputs required
    CheckOpError(stacktype{}, script, SCRIPT_ERR_INVALID_STACK_OPERATION);
    CheckOpError(stacktype{{0x01}}, script, SCRIPT_ERR_INVALID_STACK_OPERATION);

    // Length of 2nd input greater than CScriptNum::nDefaultMaxNumSize
    valtype illegal_numeric_valtype(CScriptNum::nDefaultMaxNumSize, 0x01);
    illegal_numeric_valtype.push_back(0x00);
    CheckOpError(stacktype{{0x01}, illegal_numeric_valtype}, script, SCRIPT_ERR_UNKNOWN_ERROR);

    // if n == 0, then x1 is the empty array and x2 == x;
    //execution of OP_SPLIT on empty array results in two empty arrays.
    CheckOp(stacktype{{}, {}}, script, stacktype{{}, {}});
    CheckOp(stacktype{{0x01}, {}}, script, stacktype{{}, {0x01}}); //x 0 OP_SPLIT -> OP_0 x
    CheckOp(stacktype{{0x01, 0x02, 0x03, 0x04}, {}}, script, stacktype{{}, {0x01, 0x02, 0x03, 0x04}});

    // if n == len(x) then x1 == x and x2 is the empty array
    CheckOp(stacktype{{0x01}, {0x01}}, script, stacktype{{0x01}, {}});
    CheckOp(stacktype{{0x01, 0x02, 0x03}, {0x03}}, script, stacktype{{0x01, 0x02, 0x03}, {}}); //x len(x) OP_SPLIT -> x OP_0

    // if n > len(x), then the operator must fail; x (len(x) + 1) OP_SPLIT -> FAIL
    CheckOpError(stacktype{{}, {0x01}}, script, SCRIPT_ERR_INVALID_SPLIT_RANGE);
    CheckOpError(stacktype{{0x01}, {0x02}}, script, SCRIPT_ERR_INVALID_SPLIT_RANGE);
    CheckOpError(stacktype{{0x01, 0x02, 0x03}, {0x04}}, script, SCRIPT_ERR_INVALID_SPLIT_RANGE);
    CheckOpError(stacktype{{0x01, 0x02, 0x03, 0x04}, {0x05}}, script, SCRIPT_ERR_INVALID_SPLIT_RANGE);

    // if n < 0 the operator must fail.
    CheckOpError(stacktype{{0x01, 0x02, 0x03, 0x04}, {0x81}}, script, SCRIPT_ERR_INVALID_SPLIT_RANGE);

    CheckOp(stacktype{{0x01, 0x02, 0x03, 0x04}, {0x01}}, script, stacktype{{0x01}, {0x02, 0x03, 0x04}});
    CheckOp(stacktype{{0x01, 0x02, 0x03, 0x04}, {0x02}}, script, stacktype{{0x01, 0x02}, {0x03, 0x04}});
    CheckOp(stacktype{{0x01, 0x02, 0x03, 0x04}, {0x03}}, script, stacktype{{0x01, 0x02, 0x03}, {0x04}});
    CheckOp(stacktype{{0x01, 0x02, 0x03, 0x04}, {0x04}}, script, stacktype{{0x01, 0x02, 0x03, 0x04}, {}});

    //split of a max-len valtype
    valtype maxlength_valtype(MAX_SCRIPT_ELEMENT_SIZE, 0x00);
    CheckOp(stacktype{maxlength_valtype, {}}, script, stacktype{{}, maxlength_valtype});
}

void test_cat_split(const valtype& x)
{
    CScript script;

    // x n OP_SPLIT OP_CAT -> x - for all x and for all 0 <= n <= len(x)
    script << OP_SPLIT << OP_CAT;
    CheckOp(stacktype{x, {}}, script, x);
    for (uint8_t i = 1; i <= x.size(); ++i) {
        CheckOp(stacktype{x, {i}}, script, x);
    }
}

void test_cat_split()
{
    test_cat_split({});
    test_cat_split({0x01});
    test_cat_split({0x01, 0x02});
    test_cat_split({0x01, 0x02, 0x03});
}

BOOST_AUTO_TEST_SUITE(opcodes_string)

BOOST_AUTO_TEST_CASE(op_cat)
{
    test_cat();
}

BOOST_AUTO_TEST_CASE(op_split)
{
    test_split();
}

BOOST_AUTO_TEST_CASE(cat_split)
{
    test_cat_split();
}

BOOST_AUTO_TEST_SUITE_END()
