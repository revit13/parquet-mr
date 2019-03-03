/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.parquet.hadoop;

import java.io.BufferedReader;
import java.security.SecureRandom;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.apache.hadoop.conf.Configuration;
import org.apache.parquet.crypto.KeyAccessDeniedException;
import org.apache.parquet.crypto.keytools.KmsClient;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class VaultClient implements KmsClient  {
  private String vaultAddress; 
  private String header="-H"; 
  private String TTL = "100";
  private String tokenHeader="X-Vault-Token:"; 
  private String vaultToken;
  private String strippedSecretEngine;
  private String secretEngine; 
  private String wrapTTL;
  private String wrapEndpoint;
  private String unwrapEndpoint;
  private String policiesEndpoint;
  private String appName;
  public Map<String, String> keyValues = null;

//TODO - pass a string of sensitive field names and then call createKeys() 
  public VaultClient(Configuration conf) {
    vaultAddress = conf.getTrimmed("parquet.vault.address");
    appName = conf.getTrimmed("parquet.vault.tenant");
    vaultToken = conf.getTrimmed("encryption.user.token");
    if (vaultAddress == null || appName == null || vaultToken == null) {
      throw new RuntimeException("Missing value.  vaultAddress= " + vaultAddress + " appName = " + appName + 
          " vaultToken= " + vaultToken);
    }

    wrapTTL = "X-Vault-Wrap-TTL:"+ TTL;
    strippedSecretEngine = "secret/"+appName;
    secretEngine = "/v1/"+ strippedSecretEngine;
    policiesEndpoint = "/v1/sys/policies/acl/"+ appName;
    wrapEndpoint = "/v1/auth/token/create";
    unwrapEndpoint = "/v1/sys/wrapping/unwrap";
/*    
    System.out.println("\n------ Creating a new client token using wrapped response and switch to this new client");
    createUserToken();
    // Load the stored key-values
    String lastLine = executePS_read();
    if (lastLine != null) {
      keyValues = parseReturn(lastLine, "data");    
    }
*/
  }
  
  @Override
  public boolean supportsServerSideWrapping() {
    return false;
  }

  @Override
  public String wrapDataKeyInServer(String dataKey, String masterKeyID) throws UnsupportedOperationException {
    throw new UnsupportedOperationException("should not be here for Vault");
  }

  @Override
  public String unwrapDataKeyInServer(String wrappedKey, String masterKeyID) throws UnsupportedOperationException {
    throw new UnsupportedOperationException("should not be here for Vault");
  }
  
  @Override
  public String getKeyFromServer(String keyID)  throws KeyAccessDeniedException {
    String encodedKey = keyValues.get(keyID);
    if (null == encodedKey) throw new KeyAccessDeniedException(keyID); // TODO Right thing to do?
    return (encodedKey);
  }
  
  public String writeKeys(Map <String, String> writeKeyMap) {
    // Update the cached keys
    keyValues.putAll(writeKeyMap);
    return(executePS_Post(secretEngine,  buildPayload(writeKeyMap)));
  }  
  
  public void initializeVaultClient(String[] sensitiveFields) {
    System.out.println("\n------ Creating a new client token using wrapped response and switch to this new client");
    createUserToken();
    // Load the stored key-values
    String lastLine = executePS_read();
    if (lastLine != null) {
      keyValues = parseReturn(lastLine, "data");    
    }
    writeKeys(createKeys(sensitiveFields));
  }
  
  private Map<String, String> createKeys(String[] keys) {
    Map<String, String> keyMap = new HashMap<String, String> ();
    SecureRandom random = new SecureRandom(); 
    for (int entry = 0; entry < keys.length; entry++) {
      byte[] masterKey = new byte[16]; 
      random.nextBytes(masterKey);
        keyMap.put(keys[entry], Base64.getEncoder().encodeToString(masterKey));
    }
    return keyMap;
  }
  
  private String buildPayload(Map<String, String> paramMap) {
    String jsonValue = JSONValue.toJSONString(paramMap);
    return jsonValue;
  }
  
  private String executePS_read() throws RuntimeException {
    ProcessBuilder ps = new ProcessBuilder("curl",
        header, tokenHeader+vaultToken, vaultAddress+secretEngine);
    String lastLine = null;
    try {
      lastLine = executeCurl(ps);
    } catch (IOException e) {
      System.out.println("excuteCurl failed on read ");
      e.printStackTrace();
      return null;
    }
      /* Note that if we try to read a non-existing field, executeCurl will return a string of form: {"errors":
      In that case, return null */
    if (lastLine.contains("\"errors\":[]")) {
      System.out.println("No data round in executePS_read");
      return (null);
    }
    return (lastLine);
  }
  
  private String executePS_Post(String endPoint, String jPayload) {
    String status=null;
    ProcessBuilder ps = new ProcessBuilder("curl",
        header, tokenHeader+vaultToken, "--request", "POST", "--data",  jPayload,
        vaultAddress+endPoint);
    try {
      status = executeCurl(ps);
    } catch (IOException e) {
      System.out.println("excuteCurl failed on write");
      e.printStackTrace();
      return null;
    }
    return status;
  }
  
  private String executePS_Unwrap(String wrapToken) {
    String status=null;
    ProcessBuilder ps = new ProcessBuilder("curl",
        "--trace", "curl.txt",
        header, "X-Vault-Token:"+wrapToken, "--request", "POST", 
        vaultAddress+unwrapEndpoint);
    try {
      status = executeCurl(ps);
    } catch (IOException e) {
      System.out.println("excuteCurl failed on unwrap");
      e.printStackTrace();
      return null;
    }
    return status;
  }
  
  private String executePS_Wrap_Post(String policyName) {
    String status=null;
    ProcessBuilder ps = new ProcessBuilder("curl", 
        header, wrapTTL, header, tokenHeader+vaultToken, "--request", "POST", "--data", "{\"policies\":[\"" + policyName +"\"]}",
        vaultAddress+wrapEndpoint);
    try {
      status = executeCurl(ps);
    } catch (IOException e) {
      System.out.println("excuteCurl failed on write");
      e.printStackTrace();
      return null;
    }
    return status;
  }
  
  private String executeCurl(ProcessBuilder ps) throws IOException {
    System.out.println("In executeCurl, ps =  " + ps.command());
    ps.redirectErrorStream(true);

      Process pr = ps.start(); 

      BufferedReader in = new BufferedReader(new InputStreamReader(pr.getInputStream()));

      String line;
      String lastLine = null;

      while ((line = in.readLine()) != null) {
        lastLine = line;
      }
      try {
        pr.waitFor();
      } catch (InterruptedException e) {
        in.close();
        e.printStackTrace();
      }
      in.close();
      System.out.println("in executeCurl" + lastLine);
    // If we tried to read something value that does not exist in the Vault database, curl will return a string of form {"errors":}
      return(lastLine);
  }
  
  private static Map <String, String> parseReturn(String lastLine, String searchKey) {

    JSONObject jsonObject=null;
    
    JSONParser parser = new JSONParser();
    try {
      Object obj = parser.parse(lastLine);
      jsonObject = (JSONObject) obj;
    } catch (ParseException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    
    Map<String, String> jsonMap = (Map) jsonObject.get(searchKey);
    if (jsonMap == null) {
        throw new RuntimeException(searchKey+" missing in "+lastLine);
    }
    return jsonMap;

  }
     
  private String createUserToken() throws RuntimeException {
    // Use Vault Response Wrapping to request a new user token, then unwrap that token and start using it
    String quote = "\\\"";  // i.e. \"
    Map <String, String> responseMap;
    String wrappedToken=null;
    String clientToken=null;
    String lastLine=null;
    
    // Create a policy with the same name as the passed application, with create, read, update and list privileges
    String policyLine = "{\"policy\": \"#Should have all privileges here \\npath " + quote + strippedSecretEngine + quote + "  {\\n\\tcapabilities = [" +
        quote + "create" + quote + "," + quote + "read" + quote + 
        "," + quote + "update" + quote +  "," + quote + "list" + quote + "]\\n}"+ "\"}";
    executePS_Post(policiesEndpoint,policyLine);
    
    // Create a request for a new token to be returned as a wrapped response
    lastLine = executePS_Wrap_Post(appName);
    System.out.println("wrapped token command lastLine = " + lastLine );

    responseMap = parseReturn(lastLine, "wrap_info"); // Gets the outer JSON encoding
    for (String key : responseMap.keySet()) {
      if (key.equals("token")) {
        wrappedToken = responseMap.get(key);
        System.out.println("found token key for response:" + wrappedToken);
      }
    }
//    try {
    if (wrappedToken == null) {
      throw new RuntimeException("\"token\n not found");
    }

//  Unwrap key
        System.out.println("\n----- Unwrapping response client key");
        lastLine = executePS_Unwrap(wrappedToken);
        responseMap = parseReturn(lastLine, "auth");
    for(String key: responseMap.keySet()) {
      if (key.equals("client_token")) {
        clientToken = responseMap.get(key);
        System.out.println("found client_token: "+clientToken );
      }
    }
    if (clientToken == null) {
      throw new RuntimeException("\"token\n not found");
    }
//    } catch (Exception e) {System.out.println(e);}
// Switch to the new user token
    vaultToken = clientToken;
    return lastLine;
  }
}