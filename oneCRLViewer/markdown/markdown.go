/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package markdown

import (
	"fmt"
	"strconv"
	"strings"
)

type Markdown struct {
	content strings.Builder
}

func (m *Markdown) Write(strs ...string) *Markdown {
	for _, s := range strs {
		m.content.WriteString(s)
	}
	return m
}

func (m *Markdown) WriteNL(strs ...string) *Markdown {
	m.Write(strs...)
	m.content.WriteByte('\n')
	return m
}

func (m *Markdown) H1() *Markdown {
	return m.Write("# ")
}

func (m *Markdown) H2() *Markdown {
	return m.Write("## ")
}

func (m *Markdown) H3() *Markdown {
	return m.Write("### ")
}

func (m *Markdown) H4() *Markdown {
	return m.Write("#### ")
}

func (m *Markdown) H5() *Markdown {
	return m.Write("##### ")
}

func (m *Markdown) H6() *Markdown {
	return m.Write("###### ")
}

func (m *Markdown) Italicized(s string) *Markdown {
	return m.Write("*", s, "*")
}

func (m *Markdown) Bold(s string) *Markdown {
	return m.Write("**", s, "**")
}

func (m *Markdown) Strikethrough(s string) *Markdown {
	return m.Write("~~", s, "~~")
}

func (m *Markdown) Divider() *Markdown {
	return m.WriteNL("---")
}

func (m *Markdown) OrderedList(items []interface{}) *Markdown {
	index := 1
	for _, item := range items {
		switch t := item.(type) {
		case string:
			m.WriteNL(strconv.Itoa(index), ". ", t)
			index += 1
		case fmt.Stringer:
			m.WriteNL(strconv.Itoa(index), ". ", t.String())
			index += 1
		case []interface{}:
			m.content.WriteByte('\t')
			m.OrderedList(t)
		}
	}
	return m
}

func (m *Markdown) Link(text, url string) *Markdown {
	return m.Write("[", text, "](", url, ")")
}

func (m *Markdown) Blockquote(quote string) *Markdown {
	return m.WriteNL("> ", quote)
}

func (m *Markdown) String() string {
	return m.content.String()
}

type Renderer interface {
	Render(markdown *Markdown) *Markdown
}

type Italics struct {
	Text string
}

func (i *Italics) Render(markdown *Markdown) *Markdown {
	return markdown.Italicized(i.Text)
}

type Bold struct {
	Text string
}

func (i *Bold) Render(markdown *Markdown) *Markdown {
	return markdown.Bold(i.Text)
}

type Link struct {
	Text string
	Url  string
}

func (i *Link) Render(markdown *Markdown) *Markdown {
	return markdown.Link(i.Text, i.Url)
}

func (i *Link) String() string {
	return fmt.Sprintf(" [%s](%s) ", i.Text, i.Url)
}

type Text struct {
	Text string
}

func (i *Text) Render(markdown *Markdown) *Markdown {
	return markdown.Write(i.Text)
}

type LeftAligned struct{}

func (i *LeftAligned) Render(markdown *Markdown) *Markdown {
	return markdown.Write("---")
}

type CenterAligned struct{}

func (i *CenterAligned) Render(markdown *Markdown) *Markdown {
	return markdown.Write(":---:")
}

type RightAligned struct{}

func (i *RightAligned) Render(markdown *Markdown) *Markdown {
	return markdown.Write("---:")
}

type Table struct {
	Headers    []Renderer
	Alignments []Renderer
	Rows       [][]Renderer
}

func (m *Markdown) Table(t Table) *Markdown {
	if len(t.Headers) == 0 {
		return m
	}
	m.Write("|")
	for _, header := range t.Headers {
		header.Render(m)
		m.Write("|")
	}
	m.WriteNL()
	m.Write("|")
	for _, alignment := range t.Alignments {
		alignment.Render(m)
		m.Write("|")
	}
	m.WriteNL()
	for _, row := range t.Rows {
		if len(row) == 0 {
			continue
		}
		m.Write("|")
		for _, item := range row {
			item.Render(m)
			m.Write("|")
		}
		m.WriteNL()
	}
	m.WriteNL()
	return m
}
