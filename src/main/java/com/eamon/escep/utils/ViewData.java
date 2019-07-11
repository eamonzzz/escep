package com.eamon.escep.utils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

/**
 * @author rollin
 * @date 15/5/20
 */
public class ViewData<V> implements Serializable {

    //请求成功
    public static final int CODE_SUCCESS = 0;
    //请求错误
    public static final int CODE_ERROR = -1;

    protected int code;
    protected V data;
    protected Object error;


    public ViewData success() {
        code = CODE_SUCCESS;
        this.error = null;
        return this;
    }

    public ViewData error(String error) {
        code = CODE_ERROR;
        this.error = error;
        this.data = null;

        return this;
    }

    public ViewData error(int code, String error) {
        this.code = code;
        this.error = error;
        return this;
    }

    public ViewData addError(String error) {
        code = CODE_ERROR;
        String tmpError = null;
        if (this.error instanceof String) {
            tmpError = (String) this.error;
        }

        if (this.error == null || !(this.error instanceof List)) {
            this.error = new ArrayList<String>();
        }
        if (this.error instanceof String) {
            ((List) this.error).add(tmpError);
        }
        ((List) this.error).add(error);


        return this;
    }


    public ViewData addError(int errorCode, String error) {
        code = errorCode;
        String tmpError = null;
        if (this.error instanceof String) {
            tmpError = (String) this.error;
        }

        if (this.error == null || !(this.error instanceof List)) {
            this.error = new ArrayList<String>();
        }
        if (this.error instanceof String) {
            ((List) this.error).add(tmpError);
        }
        ((List) this.error).add(error);


        return this;
    }


    public ViewData addErrors(List<String> errors) {
        if (errors == null)
            return this;

        code = CODE_ERROR;
        String tmpError = null;
        if (this.error instanceof String) {
            tmpError = (String) this.error;
        }

        if (this.error == null || !(this.error instanceof List)) {
            this.error = new ArrayList<String>();
        }
        if (this.error instanceof String) {
            ((List) this.error).add(tmpError);
        }
        ((List) this.error).addAll(errors);


        return this;
    }


    public ViewData addErrors(int errorCode, List<String> errors) {
        if (errors == null)
            return this;

        code = errorCode;
        String tmpError = null;
        if (this.error instanceof String) {
            tmpError = (String) this.error;
        }

        if (this.error == null || !(this.error instanceof List)) {
            this.error = new ArrayList<String>();
        }
        if (this.error instanceof String) {
            ((List) this.error).add(tmpError);
        }
        ((List) this.error).addAll(errors);


        return this;
    }


    public Object getValue(String key) {
        switch (key) {
            case "code":
                return code;
            case "error":
                return error;
            default:
                return data == null || !(data instanceof Map) ? null : ((Map) data).get(key);
        }
    }


    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public V getData() {
        return data;
    }

    public void setData(V data) {
        this.data = data;
    }

    public Object getError() {
        if (this.error instanceof List && ((List) this.error).size() == 1) {
            Object object = ((List) this.error).get(0);
            return object;
        } else {
            return error;
        }

    }

    public Object getError(boolean encapsulationError) {
        if (encapsulationError)
            return getError();
        else
            return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", ViewData.class.getSimpleName() + "[", "]")
                .add("code=" + code)
                .add("data=" + data)
                .add("error=" + error)
                .toString();
    }
}

