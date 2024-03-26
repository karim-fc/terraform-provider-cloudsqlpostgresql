package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

var (
	_ basetypes.StringValuable                   = CustomTimestampValue{}
	_ basetypes.StringValuableWithSemanticEquals = CustomTimestampValue{}
)

type CustomTimestampValue struct {
	basetypes.StringValue
}

func (v CustomTimestampValue) Equal(o attr.Value) bool {
	other, ok := o.(CustomTimestampValue)
	if !ok {
		return false
	}
	return v.StringValue.Equal(other.StringValue)
}

func (v CustomTimestampValue) Type(ctx context.Context) attr.Type {
	return CustomTimestampType{}
}

func (v CustomTimestampValue) StringSemanticEquals(ctx context.Context, newValuable basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	newValue, ok := newValuable.(CustomTimestampValue)

	if !ok {
		diags.AddError(
			"Semantic Equality Check Error",
			"An unexpected value type was received while performing semantic equality checks. "+
				"Please report this to the provider developers.\n\n"+
				"Expected Value Type: "+fmt.Sprintf("%T", v)+"\n"+
				"Got Value Type: "+fmt.Sprintf("%T", newValuable),
		)

		return false, diags
	}

	if v.StringValue.ValueString() == "infinity" && newValue.ValueString() == "infinity" {
		return true, diags
	}

	priorTime, _ := time.Parse(time.DateTime, v.StringValue.ValueString())
	newTime, _ := time.Parse(time.DateTime, newValue.ValueString())

	return priorTime.Equal(newTime), diags
}

func (v CustomTimestampValue) ValueTimestamp() string {
	return v.StringValue.ValueString()
}

func NewCustomTimestampValue(value string) CustomTimestampValue {
	return CustomTimestampValue{
		StringValue: types.StringValue(value),
	}
}

func NewCustomTimestampNull() CustomTimestampValue {
	return CustomTimestampValue{
		StringValue: types.StringNull(),
	}
}

func NewCustomTimestampUnknown() CustomTimestampValue {
	return CustomTimestampValue{
		StringValue: types.StringUnknown(),
	}
}
