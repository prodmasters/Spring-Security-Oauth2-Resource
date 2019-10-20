package com.prodmasters.springoauth2resource.exception;

import com.prodmasters.springoauth2resource.config.CustomTokenStore;

public class CustomTokenStoreException extends Exception {

    public CustomTokenStoreException(Exception e){
        super(e);
    }
}
