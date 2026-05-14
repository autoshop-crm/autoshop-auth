package com.vladko.autoshopauth.integration.core.dto;

import java.util.Set;

public record CoreEmployeeSyncRequest(
        String email,
        String firstName,
        String lastName,
        Set<String> roles,
        Boolean active
) {
}
