package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/attr/xattr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

var (
	_ basetypes.StringTypable = CustomTimestampType{}
	_ xattr.TypeWithValidate  = CustomTimestampType{}
)

type CustomTimestampType struct {
	basetypes.StringType
}

func (t CustomTimestampType) Equal(o attr.Type) bool {
	other, ok := o.(CustomTimestampType)

	if !ok {
		return false
	}
	return t.StringType.Equal(other.StringType)
}

func (t CustomTimestampType) String() string {
	return "CustomTimestampType"
}

func (t CustomTimestampType) ValueFromString(ctx context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	value := CustomTimestampValue{
		StringValue: in,
	}

	return value, nil
}

func (t CustomTimestampType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	attrValue, err := t.StringType.ValueFromTerraform(ctx, in)

	if err != nil {
		return nil, err
	}

	stringValue, ok := attrValue.(basetypes.StringValue)

	if !ok {
		return nil, fmt.Errorf("unexpected value type of %T", attrValue)
	}

	stringValuable, diags := t.ValueFromString(ctx, stringValue)

	if diags.HasError() {
		return nil, fmt.Errorf("unexpected error converting StringValue to StringValuable: %v", diags)
	}

	return stringValuable, nil
}

func (t CustomTimestampType) ValueType(ctx context.Context) attr.Value {
	return CustomTimestampValue{}
}

func (t CustomTimestampType) Validate(ctx context.Context, value tftypes.Value, valuePath path.Path) diag.Diagnostics {
	if value.IsNull() || !value.IsKnown() {
		return nil
	}

	var diags diag.Diagnostics
	var valueString string

	if err := value.As(&valueString); err != nil {
		diags.AddAttributeError(
			valuePath,
			"Invalid Terraform Value",
			"An unexpected error occurred while attempting to convert a Terraform value to a string. "+
				"This generally is an issue with the provider schema implementation. "+
				"Please contact the provider developers.\n\n"+
				"Path: "+valuePath.String()+"\n"+
				"Error: "+err.Error(),
		)
		return diags
	}

	if valueString == "infinity" {
		return diags
	}

	if _, err := time.Parse(time.DateTime, valueString); err != nil {
		diags.AddAttributeError(
			valuePath,
			"Invalid DateTime String Value",
			"An unexpected error occurred while converting a string value that was expected to be a DateTime format. "+
				"The string format is 'YYYY-MM-DD HH:MM:SS', such as '2006-01-02 15:04:05' or '2006-01-02 15:04:05'.\n\n"+
				"Path: "+valuePath.String()+"\n"+
				"Given Value: "+valueString+"\n"+
				"Error: "+err.Error(),
		)

		return diags
	}

	return diags
}
