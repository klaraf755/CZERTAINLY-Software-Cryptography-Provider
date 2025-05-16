package com.czertainly.cp.soft.attribute;

import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.properties.DataAttributeProperties;
import com.czertainly.cp.soft.collection.HQCSecurityCategory;

public class HQCKeyAttributes {

    private HQCKeyAttributes() {}

    public static final String ATTRIBUTE_DATA_HQC_LEVEL = "data_mldsaLevel";
    public static final String ATTRIBUTE_DATA_HQC_LEVEL_UUID = "3a495353-af2f-4a75-9ad8-7e3398318509";
    public static final String ATTRIBUTE_DATA_HQC_LEVEL_LABEL = "NIST Security Category";
    public static final String ATTRIBUTE_DATA_HQC_LEVEL_DESCRIPTION = "Security strength according NIST definition";

    public static BaseAttribute buildDataHQCSecurityCategory() {
        // define Data Attribute
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(ATTRIBUTE_DATA_HQC_LEVEL_UUID);
        attribute.setName(ATTRIBUTE_DATA_HQC_LEVEL);
        attribute.setDescription(ATTRIBUTE_DATA_HQC_LEVEL_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.INTEGER);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_HQC_LEVEL_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(HQCSecurityCategory.asIntegerAttributeContentList());

        return attribute;
    }

}
