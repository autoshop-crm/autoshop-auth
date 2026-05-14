package com.vladko.autoshopauth.integration.core.service;

import com.vladko.autoshopauth.user.entity.User;

public interface CoreEmployeeSyncService {

    void syncStaffUser(User user);
}
