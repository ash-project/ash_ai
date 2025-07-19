defmodule AshAi.ComprehensiveTypedStructTest do
  use ExUnit.Case, async: true

  # Test TypedStruct modules covering all combinations
  
  defmodule ComprehensiveExample do
    @moduledoc "Tests all field types with various constraint combinations"
    use Ash.TypedStruct
    
    typed_struct do
      # String variations with different constraints
      field :username, :string, 
        constraints: [min_length: 3, max_length: 20, match: ~r/^[a-zA-Z0-9_]+$/],
        allow_nil?: false,
        description: "Username with length and pattern constraints"
      
      field :bio, :string, 
        constraints: [max_length: 500],
        allow_nil?: true,
        description: "User biography (nullable)"
      
      field :title, :string,
        allow_nil?: true
      
      # Numeric fields with constraints
      field :age, :integer, 
        constraints: [min: 0, max: 150],
        allow_nil?: false,
        description: "Age with min/max constraints"
        
      field :score, :float,
        constraints: [greater_than: 0.0, less_than: 1.0],
        allow_nil?: true,
        description: "Score with exclusive bounds"
      
      field :rating, :float,
        constraints: [min: 1.0, max: 5.0],
        allow_nil?: false
      
      # Boolean and temporal types
      field :is_verified, :boolean, 
        allow_nil?: false, 
        default: false,
        description: "Verification status"
      
      field :created_at, :utc_datetime, 
        allow_nil?: true
      
      field :birth_date, :date,
        allow_nil?: false
      
      # Specialized types
      field :user_id, :uuid, 
        allow_nil?: false,
        description: "Unique user identifier"
      
      field :status, :atom, 
        constraints: [one_of: [:active, :inactive, :pending, :banned]],
        allow_nil?: false,
        description: "User status enum"
      
      # For now, skip array fields as TypedStruct syntax may be different
      # We'll test arrays separately once we understand the correct syntax
    end
  end

  defmodule StringConstraintsExample do
    @moduledoc "Focus on string constraint combinations"
    use Ash.TypedStruct
    
    typed_struct do
      field :basic_string, :string
      field :min_length_only, :string, constraints: [min_length: 5]
      field :max_length_only, :string, constraints: [max_length: 100]
      field :both_lengths, :string, constraints: [min_length: 3, max_length: 50]
      field :pattern_only, :string, constraints: [match: ~r/^[A-Z][a-z]+$/]
      field :all_constraints, :string, 
        constraints: [min_length: 2, max_length: 20, match: ~r/^[a-zA-Z0-9]+$/],
        allow_nil?: false
    end
  end

  defmodule NumericConstraintsExample do
    @moduledoc "Focus on numeric constraint combinations"
    use Ash.TypedStruct
    
    typed_struct do
      # Integer constraints
      field :min_only_int, :integer, constraints: [min: 0]
      field :max_only_int, :integer, constraints: [max: 100]
      field :min_max_int, :integer, constraints: [min: 10, max: 90]
      
      # Float constraints - inclusive bounds
      field :min_only_float, :float, constraints: [min: 0.0]
      field :max_only_float, :float, constraints: [max: 1.0]
      field :min_max_float, :float, constraints: [min: 0.5, max: 2.5]
      
      # Float constraints - exclusive bounds
      field :greater_than_float, :float, constraints: [greater_than: 0.0]
      field :less_than_float, :float, constraints: [less_than: 1.0]
      field :exclusive_bounds_float, :float, 
        constraints: [greater_than: 0.0, less_than: 1.0]
      
      # Mixed bounds
      field :mixed_bounds, :float,
        constraints: [min: 0.0, less_than: 10.0],
        allow_nil?: false
    end
  end

  # Skip ArrayConstraintsExample for now due to TypedStruct array syntax

  defmodule NullabilityExample do
    @moduledoc "Focus on nullability patterns"
    use Ash.TypedStruct
    
    typed_struct do
      # Non-nullable fields (should be direct types)
      field :required_string, :string, allow_nil?: false
      field :required_integer, :integer, allow_nil?: false
      field :required_boolean, :boolean, allow_nil?: false
      
      # Nullable fields (should use anyOf pattern)
      field :optional_string, :string, allow_nil?: true
      field :optional_integer, :integer, allow_nil?: true
      
      # Default nullability (should be allow_nil?: true)
      field :default_string, :string
      field :default_float, :float
    end
  end

  defmodule EdgeCaseExamples do
    defmodule EmptyStruct do
      @moduledoc "Edge case: empty TypedStruct"
      use Ash.TypedStruct
      
      typed_struct do
        # No fields
      end
    end
    
    defmodule SingleFieldStruct do
      @moduledoc "Edge case: single field"
      use Ash.TypedStruct
      
      typed_struct do
        field :name, :string, allow_nil?: false
      end
    end
    
    defmodule DefaultValuesStruct do
      @moduledoc "Edge case: fields with defaults"
      use Ash.TypedStruct
      
      typed_struct do
        field :name, :string, allow_nil?: false, default: "Anonymous"
        field :count, :integer, allow_nil?: false, default: 0
        field :active, :boolean, allow_nil?: false, default: true
        # Skip array field for now
      end
    end
  end

  alias AshAi.ComprehensiveTypedStructTest.{
    ComprehensiveExample,
    StringConstraintsExample, 
    NumericConstraintsExample,
    NullabilityExample,
    EdgeCaseExamples
  }

  describe "Comprehensive TypedStruct Schema Generation" do
    test "comprehensive example with all field types and constraints" do
      attr = %{
        type: ComprehensiveExample,
        constraints: [],
        allow_nil?: false,
        description: nil
      }
      
      schema = AshAi.OpenApi.resource_write_attribute_type(attr, nil, :create)
      
      # Verify basic structure
      assert schema[:type] == :object
      assert schema[:additionalProperties] == false
      assert is_map(schema[:properties])
      assert is_list(schema[:required])
      
      # All fields should be in required (TypedStruct behavior)
      expected_fields = [
        :username, :bio, :title, :age, :score, :rating, :is_verified, 
        :created_at, :birth_date, :user_id, :status
      ]
      assert Enum.sort(schema[:required]) == Enum.sort(expected_fields)
      
      # Test specific field schemas
      props = schema[:properties]
      
      # String with full constraints
      username_schema = props[:username]
      assert username_schema[:type] == :string
      assert username_schema[:minLength] == 3
      assert username_schema[:maxLength] == 20
      assert username_schema[:pattern] == "^[a-zA-Z0-9_]+$"
      assert username_schema[:description] == "Username with length and pattern constraints"
      refute Map.has_key?(username_schema, :anyOf)  # Non-nullable
      
      # Nullable string with constraints
      bio_schema = props[:bio]
      assert %{anyOf: bio_any_of} = bio_schema
      assert %{type: nil} in bio_any_of
      string_option = Enum.find(bio_any_of, &(&1[:type] == :string))
      assert string_option[:maxLength] == 500
      assert bio_schema[:description] == "User biography (nullable)"
      
      # Integer with constraints
      age_schema = props[:age]
      assert age_schema[:type] == :integer
      assert age_schema[:minimum] == 0
      assert age_schema[:maximum] == 150
      refute Map.has_key?(age_schema, :anyOf)  # Non-nullable
      
      # Float with exclusive constraints
      score_schema = props[:score]
      assert %{anyOf: score_any_of} = score_schema
      float_option = Enum.find(score_any_of, &(&1[:type] == :number))
      assert float_option[:exclusiveMinimum] == 0.0
      assert float_option[:exclusiveMaximum] == 1.0
      assert float_option[:format] == :float
      
      # Boolean field
      verified_schema = props[:is_verified]
      assert verified_schema[:type] == :boolean
      refute Map.has_key?(verified_schema, :anyOf)  # Non-nullable
      
      # UUID field
      user_id_schema = props[:user_id]
      assert user_id_schema[:type] == :string
      assert user_id_schema[:format] == :uuid
      
      # Atom with enum
      status_schema = props[:status]
      assert status_schema[:type] == :string
      assert status_schema[:enum] == ["active", "inactive", "pending", "banned"]
    end

    test "string constraints mapping" do
      attr = %{type: StringConstraintsExample, constraints: [], allow_nil?: false}
      schema = AshAi.OpenApi.resource_write_attribute_type(attr, nil, :create)
      
      props = schema[:properties]
      
      # Basic string (no constraints)
      assert props[:basic_string][:type] == :string
      refute Map.has_key?(props[:basic_string], :minLength)
      
      # Min length only
      assert props[:min_length_only][:minLength] == 5
      refute Map.has_key?(props[:min_length_only], :maxLength)
      
      # Max length only  
      assert props[:max_length_only][:maxLength] == 100
      refute Map.has_key?(props[:max_length_only], :minLength)
      
      # Both lengths
      assert props[:both_lengths][:minLength] == 3
      assert props[:both_lengths][:maxLength] == 50
      
      # Pattern only
      assert props[:pattern_only][:pattern] == "^[A-Z][a-z]+$"
      refute Map.has_key?(props[:pattern_only], :minLength)
      
      # All constraints
      all_constraints = props[:all_constraints]
      assert all_constraints[:minLength] == 2
      assert all_constraints[:maxLength] == 20
      assert all_constraints[:pattern] == "^[a-zA-Z0-9]+$"
      refute Map.has_key?(all_constraints, :anyOf)  # Non-nullable
    end

    test "numeric constraints mapping" do
      attr = %{type: NumericConstraintsExample, constraints: [], allow_nil?: false}
      schema = AshAi.OpenApi.resource_write_attribute_type(attr, nil, :create)
      
      props = schema[:properties]
      
      # Integer constraints
      assert props[:min_only_int][:minimum] == 0
      assert props[:max_only_int][:maximum] == 100
      assert props[:min_max_int][:minimum] == 10
      assert props[:min_max_int][:maximum] == 90
      
      # Float inclusive constraints
      assert props[:min_only_float][:minimum] == 0.0
      assert props[:max_only_float][:maximum] == 1.0
      assert props[:min_max_float][:minimum] == 0.5
      assert props[:min_max_float][:maximum] == 2.5
      
      # Float exclusive constraints
      assert props[:greater_than_float][:exclusiveMinimum] == 0.0
      assert props[:less_than_float][:exclusiveMaximum] == 1.0
      
      exclusive_bounds = props[:exclusive_bounds_float]
      assert exclusive_bounds[:exclusiveMinimum] == 0.0
      assert exclusive_bounds[:exclusiveMaximum] == 1.0
      
      # Mixed bounds
      mixed = props[:mixed_bounds]
      assert mixed[:minimum] == 0.0
      assert mixed[:exclusiveMaximum] == 10.0
      refute Map.has_key?(mixed, :anyOf)  # Non-nullable
    end

    # Skip array constraints test for now due to TypedStruct array syntax

    test "nullability patterns" do
      attr = %{type: NullabilityExample, constraints: [], allow_nil?: false}
      schema = AshAi.OpenApi.resource_write_attribute_type(attr, nil, :create)
      
      props = schema[:properties]
      
      # Non-nullable fields should be direct types
      assert props[:required_string][:type] == :string
      refute Map.has_key?(props[:required_string], :anyOf)
      
      assert props[:required_integer][:type] == :integer
      refute Map.has_key?(props[:required_integer], :anyOf)
      
      assert props[:required_boolean][:type] == :boolean
      refute Map.has_key?(props[:required_boolean], :anyOf)
      
      # Nullable fields should use anyOf pattern
      assert %{anyOf: string_any_of} = props[:optional_string]
      assert %{type: nil} in string_any_of
      assert Enum.any?(string_any_of, &(&1[:type] == :string))
      
      assert %{anyOf: int_any_of} = props[:optional_integer] 
      assert %{type: nil} in int_any_of
      assert Enum.any?(int_any_of, &(&1[:type] == :integer))
      
      # Default nullability (should be nullable)
      assert %{anyOf: default_string_any_of} = props[:default_string]
      assert %{type: nil} in default_string_any_of
      
      assert %{anyOf: default_float_any_of} = props[:default_float]
      assert %{type: nil} in default_float_any_of
    end

    test "edge case: empty TypedStruct" do
      attr = %{type: EdgeCaseExamples.EmptyStruct, constraints: [], allow_nil?: false}
      schema = AshAi.OpenApi.resource_write_attribute_type(attr, nil, :create)
      
      assert schema[:type] == :object
      assert schema[:additionalProperties] == false
      assert schema[:properties] == %{}
      assert schema[:required] == []
    end

    test "edge case: single field TypedStruct" do
      attr = %{type: EdgeCaseExamples.SingleFieldStruct, constraints: [], allow_nil?: false}
      schema = AshAi.OpenApi.resource_write_attribute_type(attr, nil, :create)
      
      assert schema[:type] == :object
      assert schema[:required] == [:name]
      assert schema[:properties][:name][:type] == :string
      refute Map.has_key?(schema[:properties][:name], :anyOf)
    end

    test "edge case: TypedStruct with default values" do
      attr = %{type: EdgeCaseExamples.DefaultValuesStruct, constraints: [], allow_nil?: false}
      schema = AshAi.OpenApi.resource_write_attribute_type(attr, nil, :create)
      
      # All fields should still be required in TypedStruct
      expected_fields = [:name, :count, :active]
      assert Enum.sort(schema[:required]) == Enum.sort(expected_fields)
      
      # Fields should have correct types
      props = schema[:properties]
      assert props[:name][:type] == :string
      assert props[:count][:type] == :integer  
      assert props[:active][:type] == :boolean
      
      # None should have anyOf (all non-nullable)
      Enum.each(props, fn {_field, field_schema} ->
        refute Map.has_key?(field_schema, :anyOf)
      end)
    end

    test "required field logic consistency" do
      # Test that all fields are always required in TypedStruct, regardless of nullability
      test_modules = [
        ComprehensiveExample,
        StringConstraintsExample,
        NumericConstraintsExample,
        NullabilityExample
      ]
      
      Enum.each(test_modules, fn module ->
        attr = %{type: module, constraints: [], allow_nil?: false}
        schema = AshAi.OpenApi.resource_write_attribute_type(attr, nil, :create)
        
        # Get expected field names from struct
        struct_map = module.__struct__()
        expected_fields = Map.keys(struct_map) |> Enum.reject(&(&1 == :__struct__))
        
        # All fields should be required
        assert Enum.sort(schema[:required]) == Enum.sort(expected_fields),
               "Module #{module} should have all fields required"
      end)
    end

    test "schema structure consistency" do
      # Test that all TypedStruct schemas have consistent structure
      test_modules = [
        ComprehensiveExample,
        StringConstraintsExample, 
        NumericConstraintsExample,
        NullabilityExample,
        EdgeCaseExamples.EmptyStruct,
        EdgeCaseExamples.SingleFieldStruct,
        EdgeCaseExamples.DefaultValuesStruct
      ]
      
      Enum.each(test_modules, fn module ->
        attr = %{type: module, constraints: [], allow_nil?: false}
        schema = AshAi.OpenApi.resource_write_attribute_type(attr, nil, :create)
        
        # Basic structure requirements
        assert schema[:type] == :object
        assert schema[:additionalProperties] == false
        assert is_map(schema[:properties])
        assert is_list(schema[:required])
        
        # Properties should match required fields
        property_fields = Map.keys(schema[:properties]) |> Enum.sort()
        required_fields = Enum.sort(schema[:required])
        assert property_fields == required_fields,
               "Module #{module} properties and required fields should match"
      end)
    end
  end
end
