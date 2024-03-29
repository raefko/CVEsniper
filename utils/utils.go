package utils

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	"golang.org/x/mod/modfile"
	"golang.org/x/net/html"
)

func compareSingleVersion(snykVersion, goModVersion string) bool {
	c, err := semver.NewConstraint(snykVersion)
	if err != nil {
		fmt.Printf("Invalid version snyk : %s err %v", snykVersion, err)
		return false
	}

	v2, err := semver.NewVersion(goModVersion)
	if err != nil {
		fmt.Printf("Invalid version go.mod : %s err %v", goModVersion, err)
		return false
	}

	return c.Check(v2)
}

func compareMultipleConstraintsVersion(constraints []string, goModVersion string) bool {
	v, err := semver.NewVersion(goModVersion)
	if err != nil {
		fmt.Printf("Invalid version: %s err %v", goModVersion, err)
		return false
	}

	for _, constraint := range constraints {
		c, err := semver.NewConstraint(constraint)
		if err != nil {
			fmt.Printf("Invalid constraint: %s err %v", constraint, err)
			return false
		}

		if !c.Check(v) {
			return false
		}
	}

	return true
}

func findNode(n *html.Node, data string) *html.Node {
	var f func(*html.Node) *html.Node
	f = func(n *html.Node) *html.Node {
		if n.Type == html.ElementNode && n.Data == data {
			return n
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			result := f(c)
			if result != nil {
				return result
			}
		}
		return nil
	}
	return f(n)
}

func findAllNodes(n *html.Node, data, version string) []*html.Node {
	var result []*html.Node
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == data {
			span := findNodeWithAttr(n, "span", "class", "vulns-table__semver")
			// Multiple span can be possible
			// Multiple version in the span can be possible
			// example here https://security.snyk.io/vuln/?search=github.com%2Fdocker%2Fdocker
			if span != nil && span.FirstChild != nil {
				snykVersion := strings.TrimSpace(span.FirstChild.Data)
				if strings.Contains(snykVersion, " ") {
					subSpans := strings.Split(snykVersion, " ")
					if len(subSpans)%3 == 0 {
						panic("Invalid version constraint")
					}
					for i := 0; i < len(subSpans)/2; i += 2 {
						compareMultipleConstraintsVersion(subSpans[i:i+2], version)
					}
				} else {
					if compareSingleVersion(snykVersion, version) {
						result = append(result, n)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)
	return result
}

func findNodeWithAttr(n *html.Node, data, attrKey, attrVal string) *html.Node {
	var f func(*html.Node) *html.Node
	f = func(n *html.Node) *html.Node {
		if n.Type == html.ElementNode && n.Data == data {
			for _, a := range n.Attr {
				if a.Key == attrKey && a.Val == attrVal {
					return n
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			result := f(c)
			if result != nil {
				return result
			}
		}
		return nil
	}
	return f(n)
}

func Snyking(module, version string) int {
	time.Sleep(200 * time.Millisecond)
	totalVulnerabilities := 0
	searchURL := "https://security.snyk.io/vuln/golang?search="
	url := searchURL + module
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return totalVulnerabilities
	}
	defer resp.Body.Close()
	doc, err := html.Parse(resp.Body)
	if err != nil {
		fmt.Println("Error:", err)
		return totalVulnerabilities
	}
	var f func(*html.Node, int) int
	f = func(n *html.Node, totalVulnerabilities int) int {
		if n.Type == html.ElementNode && n.Data == "table" {
			for _, a := range n.Attr {
				if a.Key == "class" && a.Val == "vue--table vulns-table__table" {
					tbody := findNode(n, "tbody")
					if tbody != nil {
						rows := findAllNodes(tbody, "tr", version)
						if len(rows) > 0 {
							fmt.Printf("│\n├── %s : %d vulnerabilities found for version %s\n", module, len(rows), version)
							totalVulnerabilities += len(rows)
							for i, row := range rows {
								td := findNode(row, "td")
								if td != nil {
									a := findNode(td, "a")
									if a != nil {
										for _, attr := range a.Attr {
											if attr.Key == "href" {
												link := attr.Val
												if i != len(rows)-1 {
													fmt.Printf("│  ├── https://security.snyk.io/%s\n", link)
												} else {
													fmt.Printf("│  └── https://security.snyk.io/%s\n", link)
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			totalVulnerabilities = f(c, totalVulnerabilities)
		}
		return totalVulnerabilities
	}
	totalVulnerabilities = f(doc, totalVulnerabilities)
	return totalVulnerabilities
}

func ChangeVersion(f *modfile.File, modulePath, newVersion string) {
	// Find the module
	for i, r := range f.Require {
		if r.Mod.Path == modulePath {
			// Change the version of the module
			f.Require[i].Mod.Version = newVersion
			break
		}
	}
}
