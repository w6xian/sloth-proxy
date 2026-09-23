package proxy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/w6xian/sloth/v4"
)

// TestNoHiddenSideEffects 守住"非主动，不执行"：
// 库代码里不允许出现 init()、goroutine、监听器、http.Server。
//
// 这几条一旦破戒，使用方就会在自己不知情的情况下被塞进后台任务与生命周期，
// 所以做成自动检查而不是写在注释里靠人记。
func TestNoHiddenSideEffects(t *testing.T) {
	dirs := []string{".", "http", "ssh"}
	for _, dir := range dirs {
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", dir, err)
		}
		for _, pkg := range pkgs {
			for name, file := range pkg.Files {
				ast.Inspect(file, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.FuncDecl:
						if x.Recv == nil && x.Name.Name == "init" {
							t.Errorf("%s: 不允许 init()：库不能主动执行任何东西", name)
						}
					case *ast.GoStmt:
						t.Errorf("%s:%d: 不允许启动 goroutine（后台任务属于调用方）",
							name, fset.Position(x.Go).Line)
					case *ast.CompositeLit:
						if sel, ok := x.Type.(*ast.SelectorExpr); ok {
							if id, ok := sel.X.(*ast.Ident); ok && id.Name == "http" && sel.Sel.Name == "Server" {
								t.Errorf("%s:%d: 不允许创建 http.Server（只返回 Handler）",
									name, fset.Position(x.Lbrace).Line)
							}
						}
					case *ast.SelectorExpr:
						if id, ok := x.X.(*ast.Ident); ok && id.Name == "net" &&
							(x.Sel.Name == "Listen" || x.Sel.Name == "Dial") {
							t.Errorf("%s:%d: 库代码不监听/拨号（net.%s）",
								name, fset.Position(x.Sel.Pos()).Line, x.Sel.Name)
						}
					}
					return true
				})
			}
		}
	}
}

// TestSlothTypesSatisfyContracts 编译期已断言，这里再显式确认一次，
// 免得有人把断言删掉（删了就失去了"sloth 改签名立刻报错"的保护）。
func TestSlothTypesSatisfyContracts(t *testing.T) {
	var (
		_ Caller   = (*sloth.ClientRpc)(nil)
		_ Resolver = (*sloth.SMap)(nil)
	)
	_ = SlothLogger()
}
