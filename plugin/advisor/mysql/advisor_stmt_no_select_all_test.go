package mysql

import (
	"testing"

	"github.com/bytebase/bytebase/common"
	"github.com/bytebase/bytebase/plugin/advisor"
)

func TestNoSelectAll(t *testing.T) {
	tests := []test{
		{
			statement: "SELECT * FROM t",
			want: []advisor.Advice{
				{
					Status:  advisor.Error,
					Code:    common.StatementSelectAll,
					Title:   "statement.select.no-select-all",
					Content: "\"SELECT * FROM t\" uses SELECT all",
				},
			},
		},
		{
			statement: "SELECT a, b FROM t",
			want: []advisor.Advice{
				{
					Status:  advisor.Success,
					Code:    common.Ok,
					Title:   "OK",
					Content: "",
				},
			},
		},
		{
			statement: "SELECT a, b FROM (SELECT * from t1 JOIN t2) t",
			want: []advisor.Advice{
				{
					Status:  advisor.Error,
					Code:    common.StatementSelectAll,
					Title:   "statement.select.no-select-all",
					Content: "\"SELECT a, b FROM (SELECT * from t1 JOIN t2) t\" uses SELECT all",
				},
			},
		},
	}

	runSchemaReviewRuleTests(t, tests, &NoSelectAllAdvisor{}, &advisor.SchemaReviewRule{
		Type:    advisor.SchemaRuleStatementNoSelectAll,
		Level:   advisor.SchemaRuleLevelError,
		Payload: "",
	}, &MockCatalogService{})
}
