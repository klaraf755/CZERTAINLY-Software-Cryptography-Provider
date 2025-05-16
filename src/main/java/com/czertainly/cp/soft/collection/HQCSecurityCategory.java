package com.czertainly.cp.soft.collection;

import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.IntegerAttributeContent;
import org.bouncycastle.pqc.jcajce.spec.HQCParameterSpec;
import org.springframework.lang.Nullable;

import java.util.List;
import java.util.stream.Collectors;

public enum HQCSecurityCategory {

    CATEGORY_1(1, 17992 , 448, HQCParameterSpec.hqc128),
    CATEGORY_3(3, 36176 , 512, HQCParameterSpec.hqc192),
    CATEGORY_5(5, 57960, 576, HQCParameterSpec.hqc256);

    private static final HQCSecurityCategory[] VALUES;

    static {
        VALUES = values();
    }

    private final int nistSecurityCategory;
    private final int publicKeySize;
    private final int privateKeySize;
    private final HQCParameterSpec parameterSet;

    HQCSecurityCategory(int nistLevel, int publicKeySize, int privateKeySize, HQCParameterSpec parameterSet) {
        this.nistSecurityCategory = nistLevel;
        this.publicKeySize = publicKeySize;
        this.privateKeySize = privateKeySize;
        this.parameterSet = parameterSet;
    }

    public int getNistSecurityCategory() {
        return nistSecurityCategory;
    }

    public int getPublicKeySize() {
        return publicKeySize;
    }

    public int getPrivateKeySize() {
        return privateKeySize;
    }

    public HQCParameterSpec getParameterSet() {return parameterSet;}

    @Override
    public String toString() {
        return name();
    }

    public static HQCSecurityCategory valueOf(int nistLevel) {
        HQCSecurityCategory d = resolve(nistLevel);
        if (d == null) {
            throw new IllegalArgumentException("No matching constant for [" + nistLevel + "]");
        }
        return d;
    }

    @Nullable
    public static HQCSecurityCategory resolve(int nistLevel) {
        // Use cached VALUES instead of values() to prevent array allocation.
        for (HQCSecurityCategory d : VALUES) {
            if (d.nistSecurityCategory == nistLevel) {
                return d;
            }
        }
        return null;
    }

    public static List<BaseAttributeContent> asIntegerAttributeContentList() {
        return List.of(values()).stream()
                .map(d -> new IntegerAttributeContent(d.name(), d.getNistSecurityCategory()))
                .collect(Collectors.toList());
    }
}
