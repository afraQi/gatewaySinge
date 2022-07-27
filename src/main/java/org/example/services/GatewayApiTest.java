package org.example.services;

import com.alibaba.fastjson.JSON;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.internal.LinkedTreeMap;
import org.apache.commons.lang.StringUtils;
import org.example.services.utils.MD5Utils;
import org.example.services.utils.RSA;
import org.example.services.utils.RSAUtils;
import org.junit.Test;

import java.util.*;
import java.util.stream.Collectors;

public class GatewayApiTest {
    //我方分配
    private static String url = "xxxxx";
    //用来加密 我方分配
    String rsaPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCcGsFTFtEpT+ZRNkNqx2RPnNhI\n" +
            "ulx2qwq8eG4J00ZCqg6zDtoFQJtz4XEZQGjlL95xlXDd7VmqLtTd5jVcHL1eohWc\n" +
            "BczmR1Qab8299v2Yn3X4I6DEAHl+P4trOqd9LNs7WIlBLddV5VOB2TrBjSq05v/0\n" +
            "gLXs8dppnzHwOvRV1wIDAQAB";

    //用来解密 我方分配
    String rsaPrivateKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAJwawVMW0SlP5lE2\n" +
            "Q2rHZE+c2Ei6XHarCrx4bgnTRkKqDrMO2gVAm3PhcRlAaOUv3nGVcN3tWaou1N3m\n" +
            "NVwcvV6iFZwFzOZHVBpvzb32/ZifdfgjoMQAeX4/i2s6p30s2ztYiUEt11XlU4HZ\n" +
            "OsGNKrTm//SAtezx2mmfMfA69FXXAgMBAAECgYAOVjq5KdhN5gOuI8CvVt60nSAU\n" +
            "FeGWGIFk696XUmsahknRUiTd5KAiVWswuYSov+u7HNF/4GOiyKhONO1jp1QQ7yzO\n" +
            "rW8nbjme2opFZHxTLOOmQMmQksqlMCAm0WoE+/GJ6pQgllE7oTv5uzaXdUR0PnvF\n" +
            "v/wLwwIphdL0h5enoQJBAM+tDP3t/Q6oJftmKpfDnpTER50Kzkh11u/iQzJix5gg\n" +
            "ZXqktSJiQIMIcrVIap4gRCSx+2inr5Gt1E1cE4SEZ6cCQQDAbas4G/M+J/mNPOtA\n" +
            "3uM8SzlVIPtGfLNQn+MFd9u71kZGGCGcXxjEQtoYUlkmwuwlnbXnXXzUwe7ZnqP+\n" +
            "hWZRAkAiKciSWT0g1R5ybcsh7ic/N87EEcv/dYsnKSR+vGszJlkrRL8baehM5e3g\n" +
            "zonje1FabAD8pWEnaN4c38HCMfnPAkAeMtfVBWXmEkXyqWXOF2yX8MI9nuBwTm+h\n" +
            "roXlPMsqLlV2+KCFttLfMhKiEIJXN+3xdU+v0JcfmJPQaToZXnwRAkB0nPwxA5GH\n" +
            "ew7I33/xvjCRQuz832Hp6cBS2JPY9LoxbN/2Rq7SwIYo9+D/98+ZdEX2WAkv9Mmc\n" +
            "NC5LgZvJ5atS";
    // 机构code  我方分配
    String orgCode = "ORG_202107281634411436";
    //请求的方法名 我方分配
    String serviceId = "TOKEN_GET_USERINFO";

    @Test
    /**
     * 请求&加密示例
     */
    public void req() throws Exception {
        String requestJson = "{\n" +
                "    \"mobileMd5\": \"578f3b822b0017d6e630bf7569fe2317\",\n" +
                "    \"timestamp\": \"1658857690387\"\n" +
                "}";


        TreeMap<String, Object> originMap = new TreeMap<>(JSON.parseObject(requestJson, TreeMap.class));
        String strBuild = getSortedParams(originMap);


        System.out.println("原始参数" + requestJson);
        System.out.println("MD5加密数据" + strBuild);
        String signature = MD5Utils.md5(strBuild);
        System.out.println("MD5生成sige=" + signature);
        System.out.println("RSA加密数据" + requestJson);
        String data = RSA.encryptedDataOnJava(requestJson, rsaPublicKey);

        Map<String, String> resultMap = new HashMap<>();

        resultMap.put("sign", signature);
        resultMap.put("serviceId", serviceId);
        resultMap.put("orgCode", orgCode);
        resultMap.put("data", data);
        String content = JSON.toJSONString(resultMap);
        System.out.println("最终发送的正文:" + content);
        //content则是最终需发送的请求正文
    }

    @Test
    /**
     * 响应示例
     */
    public void resp() throws Exception {
        // code,msg为响应公参,param里面为具体业务响应信息
        String respJson = "{\n" +
                "    \"code\": \"0000\",\n" +
                "    \"msg\": \"成功\",\n" +
                "    \"param\": {\n" +
                "        \"remark\": \"可以推送\",\n" +
                "        \"result\": \"0\"\n" +
                "    }\n" +
                "}";


        TreeMap<String, Object> originMap = new TreeMap<>(JSON.parseObject(respJson, TreeMap.class));
        String strBuild = getSortedParams(originMap);


        System.out.println("原始参数" + respJson);
        System.out.println("MD5加密数据" + strBuild);
        String signature = MD5Utils.md5(strBuild);
        System.out.println("MD5生成sige=" + signature);
        String data = RSA.encryptedDataOnJava(respJson, rsaPublicKey);

        Map<String, String> resultMap = new HashMap<>();

        resultMap.put("data", signature);
        resultMap.put("sign", data);
        String content = JSON.toJSONString(resultMap);
        System.out.println("最终发送的正文:" + content);
        //content则是最终需发送的请求正文
    }

    @Test
    /**
     * 解密示例
     */
    public void decrypt() throws Exception {
        // code,msg为响应公参,param里面为具体业务响应信息
        String reqStr = "{\"data\":\"ds6u+HV2IPwwKRvy03GQzTph/cGBZtNiZbMaMY6Kw1dmdHfpHPNZ1XaK64tb/GQB7kVnLKh9GW/A\\r\\n2gsj9yyUu2BeHHeoxeAF+PCAPNegPm4TtZ5wkk7pOtjSgUEri5SIhz2ZmR1/7k6+R/saJg/yuCpj\\r\\nR2M/7aVYsE/OsVaTHLw=\\r\\n\",\"orgCode\":\"ORG_202107281634411436\",\"sign\":\"afcb7d254677144c305421a6808813e7\",\"serviceId\":\"TOKEN_GET_USERINFO\"}";
        TreeMap<String, Object> originalMap = new TreeMap<>(JSON.parseObject(reqStr, TreeMap.class));

        // 参数解密
        Map<String, Object> params = null;
        String paramsStr = "";

        paramsStr = RSA.decryptDataOnJava((String) originalMap.get("data"), rsaPrivateKey);
        params = JSON.parseObject(paramsStr, TreeMap.class);
        JsonObject jsonObject = new JsonParser().parse(paramsStr).getAsJsonObject();
        if (jsonObject.get("param") != null) {
            params.put("param", JSON.parseObject(jsonObject.get("param").toString(), LinkedTreeMap.class));
        }


        String sortedParams = getSortedParams(params);

        String signature = (String) originalMap.get("sign");


        String ourSignature = MD5Utils.md5(sortedParams);
        if (!signature.equals(ourSignature)) {
            System.out.println("验证签名失败");
        }else {
            System.out.println("最终解密得到数据:"+paramsStr);
        }

    }


    /**
     * 对map进行排序，排除空值，并且得到key1=val1&key2=val2字符串
     *
     * @param params
     * @return
     */
    public static String getSortedParams(Map<String, Object> params) {
        List<String> keys = params.keySet().stream().sorted().collect(Collectors.toList());
        StringBuilder sb = new StringBuilder(); // new 一个sb
        for (String key : keys) {
            if (params.get(key) != null) {
                if (params.get(key) instanceof List || params.get(key) instanceof Map || params.get(key) instanceof Collection) {
                    sb.append(key).append("=").append(JSON.toJSONString(params.get(key))).append("&");
                } else {
                    sb.append(key).append("=").append(String.valueOf(params.get(key))).append("&");
                }

            }

        }
        return sb.substring(0, sb.lastIndexOf("&"));
    }


}
