package com.atwo.paganois.shared.dtos;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public class CustomErrorResponse {

    private Instant timestamp;
    private Integer status;
    private String error;
    private String path;
    private Map<String, List<String>> errors;

    public CustomErrorResponse(Instant timestamp, Integer status, String error, String path) {
        this.timestamp = timestamp;
        this.status = status;
        this.error = error;
        this.path = path;
    }

    public CustomErrorResponse(Instant timestamp, Integer status, Map<String, List<String>> errors,
            String path) {
        this.timestamp = timestamp;
        this.status = status;
        this.path = path;
        this.errors = errors;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public Integer getStatus() {
        return status;
    }

    public String getError() {
        return error;
    }

    public String getPath() {
        return path;
    }

    public Map<String, List<String>> getErrors() {
        return errors;
    }



}
