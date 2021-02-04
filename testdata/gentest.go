// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
)

var (
	prfs = map[string]string{
		"HMAC_SHA1": "NewHMACPRF(crypto.SHA1)",
		"HMAC_SHA224": "NewHMACPRF(crypto.SHA224)",
		"HMAC_SHA256": "NewHMACPRF(crypto.SHA256)",
		"HMAC_SHA384": "NewHMACPRF(crypto.SHA384)",
		"HMAC_SHA512": "NewHMACPRF(crypto.SHA512)",
	}
)

func scanTokens(data []byte, atEOF bool) (int, []byte, error) {
	// Scan until the end of the line
	lineAdv, tok, err := bufio.ScanLines(data, atEOF)
	switch {
	case err != nil:
		return 0, nil, err
	case lineAdv == 0:
		// Request a new line
		return 0, nil, nil
	case len(tok) == 0:
		// Return a newline as a token
		return lineAdv, []byte{'\n'}, nil
	}

	// Skip space
	adv := strings.IndexFunc(string(tok), func(r rune) bool {
		return !unicode.IsSpace(r)
	})
	if adv < 0 {
		// The rest of the line is all space - request a new one
		return lineAdv, []byte{'\n'}, nil
	}
	tok = tok[adv:]

	// The rest of the line is a comment - request a new one
	if tok[0] == '#' {
		return lineAdv, []byte{'\n'}, nil
	}

	// Find the next delimiter
	i := strings.IndexAny(string(tok), "[]=")
	switch {
	case i == 0:
		tok = []byte{tok[0]}
	case i >= 0:
		tok = tok[:i]
	}

	tok = []byte(strings.TrimSpace(string(tok)))

	return adv + len(tok), tok, nil
}

type testCase struct {
	l string
	key string
	iv string
	fixed string
	expected string
}

type testSuite struct {
	prf string
	ctrLocation string
	rlen string
	tests []*testCase
}

type stateFunc func(string) (stateFunc, error)

type parser struct {
	scanner *bufio.Scanner
	current stateFunc

	suites []*testSuite
	currentSuite *testSuite
	currentTest *testCase
	currentName string
}

func (p *parser) handleEndTestCaseParam(tok string) (stateFunc, error) {
	switch {
	case tok == "\n":
		return p.handleStartTestCaseParam, nil
	default:
		return nil, fmt.Errorf("handleEndTestCaseParam: unexpected token %v", tok)
	}
}

func (p *parser) handleTestCaseParam(tok string) (stateFunc, error) {
	switch p.currentName {
	case "L":
		p.currentTest.l = tok
	case "KI":
		p.currentTest.key = tok
	case "IV":
		p.currentTest.iv = tok
	case "FixedInputData":
		p.currentTest.fixed = tok
	case "KO":
		p.currentTest.expected = tok
	}

	return p.handleEndTestCaseParam, nil
}

func (p *parser) handleEndTestSuiteParam2(tok string) (stateFunc, error) {
	switch {
	case tok == "\n":
		return p.handleStartTestSuiteParam, nil
	default:
		return nil, fmt.Errorf("handleEndTestSuiteParam2: unexpected token %v", tok)
	}
}

func (p *parser) handleEndTestSuiteParam(tok string) (stateFunc, error) {
	switch {
	case tok == "]":
		return p.handleEndTestSuiteParam2, nil
	default:
		return nil, fmt.Errorf("handleEndTestSuiteParam: unexpected token %v", tok)
	}
}

func (p *parser) handleTestSuiteParam(tok string) (stateFunc, error) {
	switch p.currentName {
	case "PRF":
		p.currentSuite.prf = tok
	case "CTRLOCATION":
		p.currentSuite.ctrLocation = tok
	case "RLEN":
		p.currentSuite.rlen = tok
	}

	return p.handleEndTestSuiteParam, nil
}

func (p *parser) handleParamValue(tok string) (stateFunc, error) {
	switch {
	case tok == "[" || tok == "]" || tok == "=":
		return nil, fmt.Errorf("handleParamValue: unexpected token %v", tok)
	case tok == "\n" && p.currentTest != nil:
		return p.handleStartTestCaseParam, nil
	case tok == "\n":
		return nil, fmt.Errorf("handleParamValue: unexpected token %v", tok)
	case p.currentTest != nil:
		return p.handleTestCaseParam(tok)
	default:
		return p.handleTestSuiteParam(tok)
	}
}

func (p *parser) handleEqual(tok string) (stateFunc, error) {
	switch {
	case tok == "=":
		return p.handleParamValue, nil
	default:
		return nil, fmt.Errorf("handleEqual: unexpected token %v", tok)
	}
}

func (p *parser) handleParamName(tok string) (stateFunc, error) {
	switch {
	case tok == "\n" || tok == "[" || tok == "]" || tok == "=":
		return nil, fmt.Errorf("handleParamName: unexpected token %v", tok)
	default:
		p.currentName = string(tok)
		return p.handleEqual, nil
	}
}

func (p *parser) handleStartTestCaseParam(tok string) (stateFunc, error) {
	switch {
	case tok == "\n":
		p.currentSuite.tests = append(p.currentSuite.tests, p.currentTest)
		p.currentTest = nil
		return p.start, nil
	case tok == "[" || tok == "]" || tok == "=":
		return nil, fmt.Errorf("handleStartTestCaseParam: unexpected token %v", tok)
	default:
		return p.handleParamName(tok)
	}
}

func (p *parser) handleStartTestSuiteParam2(tok string) (stateFunc, error) {
	switch {
	case tok == "[" || tok == "]" || tok == "=" || tok == "\n":
		return nil, fmt.Errorf("handleStartTestSuiteParam2: unexpected token %v", tok)
	default:
		return p.handleParamName(tok)
	}
}

func (p *parser) handleStartTestSuiteParam(tok string) (stateFunc, error) {
	switch {
	case tok == "\n":
		return p.start, nil
	case tok == "[":
		return p.handleStartTestSuiteParam2, nil
	case tok == "]" || tok == "=":
		return nil, fmt.Errorf("handleStartTestSuiteParam: unexpected token %v", tok)
	default:
		p.currentTest = &testCase{}
		return p.handleStartTestCaseParam(tok)
	}
}

func (p *parser) start(tok string) (stateFunc, error) {
	switch {
	case tok == "\n":
		return nil, nil
	case tok == "[":
		p.currentSuite = &testSuite{}
		p.suites = append(p.suites, p.currentSuite)
		return p.handleStartTestSuiteParam(tok)
	case tok == "]" || tok == "=":
		return nil, fmt.Errorf("start: unexpected token %v", tok)
	default:
		if p.currentSuite == nil {
			return nil, fmt.Errorf("start: unexpected token %v (no current suite)", tok)
		}
		p.currentTest = &testCase{}
		return p.handleStartTestCaseParam(tok)
	}
}

func (p *parser) run() error {
	for p.scanner.Scan() {
		next, err := p.current(p.scanner.Text())
		if err != nil {
			return err
		}
		if next != nil {
			p.current = next
		}
	}
	return nil
}

func newParser(r io.Reader) *parser {
	scanner := bufio.NewScanner(r)
	scanner.Split(scanTokens)
	p := &parser{scanner: scanner}
	p.current = p.start
	return p
}

func generateTests(w io.Writer, vectors, ctrLocation, rlen, suiteTpl, testTpl string) error {
	f, err := os.Open(vectors)
	if err != nil {
		return err
	}
	defer f.Close()

	parser := newParser(f)
	if err := parser.run(); err != nil {
		return err
	}

	for _, suite := range parser.suites {
		if suite.ctrLocation != ctrLocation {
			continue
		}
		if suite.rlen != rlen {
			continue
		}
		newPrf, ok := prfs[suite.prf]
		if !ok {
			continue
		}

		fmt.Fprintf(w, suiteTpl, suite.prf, newPrf)

		for i, test := range suite.tests {
			fmt.Fprintf(w, testTpl, suite.prf, i, test.key, test.fixed, test.iv, test.l, test.expected)
		}
	}

	return nil
}

func run(in io.Reader, out io.Writer) error {
	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("cannot copy test prologue: %v", err)
	}

	if err := generateTests(out, "testdata/KDFCTR_gen.rsp", "BEFORE_FIXED", "32_BITS", `

func (s *kdfSuite) testCounterMode%[1]s(c *C, data *testData) {
	s.testCounterMode(c, %[2]s, data)
}`, `

func (s *kdfSuite) TestCounterMode%[1]s_%[2]d(c *C) {
	s.testCounterMode%[1]s(c, &testData{
		key: decodeHexString(c, "%[3]s"),
		fixed: decodeHexString(c, "%[4]s"),
		bitLength: %[6]s,
		expected: decodeHexString(c, "%[7]s"),
	})
}`); err != nil {
	return err
}

	if err := generateTests(out, "testdata/FeedbackModenocounter/KDFFeedback_gen.rsp", "", "", `

func (s *kdfSuite) testFeedbackModeNoCounter%[1]s(c *C, data *testData) {
	s.testFeedbackMode(c, %[2]s, data, false)
}`, `

func (s *kdfSuite) TestFeedbackModeNoCounter%[1]s_%[2]d(c *C) {
	s.testFeedbackModeNoCounter%[1]s(c, &testData{
		key: decodeHexString(c, "%[3]s"),
		fixed: decodeHexString(c, "%[4]s"),
		iv: decodeHexString(c, "%[5]s"),
		bitLength: %[6]s,
		expected: decodeHexString(c, "%[7]s"),
	})
}`); err != nil {
	return err
}

	if err := generateTests(out, "testdata/FeedbackModeNOzeroiv/KDFFeedback_gen.rsp", "AFTER_ITER", "32_BITS", `

func (s *kdfSuite) testFeedbackModeNoZeroIV%[1]s(c *C, data *testData) {
	s.testFeedbackMode(c, %[2]s, data, true)
}`, `

func (s *kdfSuite) TestFeedbackModeNoZeroIV%[1]s_%[2]d(c *C) {
	s.testFeedbackModeNoZeroIV%[1]s(c, &testData{
		key: decodeHexString(c, "%[3]s"),
		fixed: decodeHexString(c, "%[4]s"),
		iv: decodeHexString(c, "%[5]s"),
		bitLength: %[6]s,
		expected: decodeHexString(c, "%[7]s"),
	})
}`); err != nil {
	return err
}

	if err := generateTests(out, "testdata/FeedbackModewzeroiv/KDFFeedback_gen.rsp", "AFTER_ITER", "32_BITS", `

func (s *kdfSuite) testFeedbackModeZeroIV%[1]s(c *C, data *testData) {
	s.testFeedbackMode(c, %[2]s, data, true)
}`, `

func (s *kdfSuite) TestFeedbackModeZeroIV%[1]s_%[2]d(c *C) {
	s.testFeedbackModeZeroIV%[1]s(c, &testData{
		key: decodeHexString(c, "%[3]s"),
		fixed: decodeHexString(c, "%[4]s"),
		iv: decodeHexString(c, "%[5]s"),
		bitLength: %[6]s,
		expected: decodeHexString(c, "%[7]s"),
	})
}`); err != nil {
	return err
}

	if err := generateTests(out, "testdata/PipelineModewithCounter/KDFDblPipeline_gen.rsp", "AFTER_ITER", "32_BITS", `

func (s *kdfSuite) testPipelineMode%[1]s(c *C, data *testData) {
	s.testPipelineMode(c, %[2]s, data, true)
}`, `

func (s *kdfSuite) TestPipelineMode%[1]s_%[2]d(c *C) {
	s.testPipelineMode%[1]s(c, &testData{
		key: decodeHexString(c, "%[3]s"),
		fixed: decodeHexString(c, "%[4]s"),
		bitLength: %[6]s,
		expected: decodeHexString(c, "%[7]s"),
	})
}`); err != nil {
	return err
}

	if err := generateTests(out, "testdata/PipelineModeWOCounterr/KDFDblPipeline_gen.rsp", "", "", `

func (s *kdfSuite) testPipelineModeNoCounter%[1]s(c *C, data *testData) {
	s.testPipelineMode(c, %[2]s, data, false)
}`, `

func (s *kdfSuite) TestPipelineModeNoCounter%[1]s_%[2]d(c *C) {
	s.testPipelineModeNoCounter%[1]s(c, &testData{
		key: decodeHexString(c, "%[3]s"),
		fixed: decodeHexString(c, "%[4]s"),
		bitLength: %[6]s,
		expected: decodeHexString(c, "%[7]s"),
	})
}`); err != nil {
	return err
}

	return nil
}

func main() {
	src, err := os.Open("testdata/kdf_test.go.in")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open source file: %v\n")
		os.Exit(1)
	}

	dst, err := os.OpenFile(".kdf_test.go", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open destination file: %v\n")
		os.Exit(1)
	}

	if err := run(src, dst); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Remove(dst.Name())
		os.Exit(1)
	}

	if err := os.Rename(dst.Name(), "kdf_test.go"); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot update destination file: %v\n")
		os.Remove(dst.Name())
		os.Exit(1)
	}
}
