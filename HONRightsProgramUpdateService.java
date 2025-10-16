package com.hon.aecs.prm.syncProgramMembers.services;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.json.JSONObject;

import com.hon.aecs.prm.syncProgramMembers.clientx.AppXSession;
import com.hon.aecs.prm.syncProgramMembers.constant.Constants;
import com.teamcenter.services.strong.core.DataManagementService;
import com.teamcenter.services.strong.core.SessionService;
import com.teamcenter.services.strong.core._2010_09.DataManagement.NameValueStruct1;
import com.teamcenter.services.strong.core._2010_09.DataManagement.PropInfo;
import com.teamcenter.services.strong.core._2010_09.DataManagement.SetPropertyResponse;
import com.teamcenter.services.strong.query.SavedQueryService;
import com.teamcenter.services.strong.query._2007_06.SavedQuery.ExecuteSavedQueriesResponse;
import com.teamcenter.services.strong.query._2007_06.SavedQuery.SavedQueryInput;
import com.teamcenter.services.strong.query._2007_06.SavedQuery.SavedQueryResults;
import com.teamcenter.services.strong.query._2010_04.SavedQuery.FindSavedQueriesCriteriaInput;
import com.teamcenter.services.strong.query._2010_04.SavedQuery.FindSavedQueriesResponse;
import com.teamcenter.soa.client.Connection;
import com.teamcenter.soa.client.model.ModelObject;
import com.teamcenter.soa.client.model.strong.ImanQuery;
import com.teamcenter.soa.client.model.strong.WorkspaceObject;
import com.teamcenter.soa.common.ObjectPropertyPolicy;
import com.teamcenter.soa.common.PolicyProperty;
import com.teamcenter.soa.common.PolicyType;

public class HONRightsProgramUpdateService {
	@SuppressWarnings("null")
	public String updateRightsProgramInTC(Map<String, String[]> programRightMemberMap) {
		
		String result = "";
		String LocalPath = "";
		String OsName = "";
		String serverHost = null;
		String userID = "";
		String userPassword = "";
		String queryName = "";
		
		ImanQuery query = null;
		
		StringBuilder failurls = new StringBuilder();
		StringBuilder successurls = new StringBuilder();
		boolean anySuccess = false;
		
		try {
			// getting system ENV
			//LocalPath = System.getenv(Constants.getTcAecsHomeValue());
			LocalPath = "D:\\SPLM\\TC14\\TC_ROOT\\TC_AECS_HOME";
			System.out.println("LocalPath : " + LocalPath);
			
			OsName = System.getProperty(Constants.getOSNameValue());
			System.out.println("OsName : "+ OsName);

			InputStream inputStream = null;
			Properties properties = new Properties();
			
			if (OsName.contains("Win")) {
				inputStream = new FileInputStream(LocalPath + "\\HON_Login_Details.properties");
			} else {
				inputStream = new FileInputStream(LocalPath + "/HON_Login_Details.properties");
			}
			properties.load(inputStream);
			
			List<String> requiredFileds=Arrays.asList("SERVERHOST","USER_ID","USER_PASS","QUERY");
			StringBuilder errors=new StringBuilder();
			
			for(String filed:requiredFileds)
			{
				String value=properties.getProperty(filed);
				if(value==null)
				{
					errors.append(filed).append(" is Missing\n");
				}else if(value.trim().isEmpty())
				{
					errors.append(filed).append(" is Empty\n");
				}
			}
			
			System.out.println("Errors Length : " + errors.length());
			
			if(errors.length()>0)
			{
				return errors.toString();
			}
			
			serverHost = properties.getProperty("SERVERHOST");
			userID = properties.getProperty("USER_ID");
			userPassword = properties.getProperty("USER_PASS");

			AppXSession session = new AppXSession(serverHost);
			String loginUser = "";
			loginUser = session.login(userID, userPassword);

			if (loginUser.equals("null")) {
				failurls.append(serverHost).append("\n");
			} else {
				successurls.append(serverHost).append("\n");
				anySuccess = true;
			}
			

			if (!anySuccess) {
				String res = "\nConnection is failed for following Site:\n" + failurls.toString().trim();
				return res.toString().trim();
			} else if (failurls.length() > 0) {
				return "\nPartial Success.\nScuccessful Site(s):" + successurls.toString().trim() + "\nFailed Site(s):"
						+ failurls.toString().trim();
			} else {
				DataManagementService dmService = DataManagementService.getService(AppXSession.getConnection());
				SavedQueryService queryService = SavedQueryService.getService(AppXSession.getConnection());
				SessionService sessionService = SessionService.getService(AppXSession.getConnection());
				
				String aecsPRMName = (String) programRightMemberMap.keySet().toArray()[0];
				System.out.println("aecsPRMName : " + aecsPRMName);
				
				queryName = properties.getProperty("QUERY");
				FindSavedQueriesCriteriaInput[] input = new FindSavedQueriesCriteriaInput[1];
				input[0] = new FindSavedQueriesCriteriaInput();
				input[0].queryNames = new String[] { queryName };
				FindSavedQueriesResponse response = queryService.findSavedQueries(input);
				if (response != null && response.savedQueries.length == 1) 
				{
					query = response.savedQueries[0];
				} else 
				{
					result = "Employee Information query not found, please contact sys admin.";		
					return result;
				}
				
				SavedQueryInput savedQueryInput[] = new SavedQueryInput[1];
				savedQueryInput[0] = new SavedQueryInput();
				
				savedQueryInput[0].query = query; 
				savedQueryInput[0].entries = new String[] {"Type" }; 
				savedQueryInput[0].values = new String[] { "Rights Program" };
				
				ExecuteSavedQueriesResponse executeSavedQueryResponse = queryService.executeSavedQueries(savedQueryInput);
				if (executeSavedQueryResponse.serviceData.sizeOfPartialErrors() > 0) 
				{
					int errorCount = executeSavedQueryResponse.serviceData.sizeOfPartialErrors();
					System.out.println("ExecuteSavedQueriesResponse error count : " + errorCount);
					for(int enx=0; enx < errorCount; enx++) {
						result += executeSavedQueryResponse.serviceData.getPartialError(enx);
					}
					System.out.println("result : "+ result);
					return result.trim();
				} 
				else 
				{
					SavedQueryResults found = executeSavedQueryResponse.arrayOfResults[0];
					ModelObject honRightsProgram[] = found.objects;
					int totalRightsProgram=honRightsProgram.length;
					System.out.println("\n Total Rights Program found: " + totalRightsProgram);
					
					ObjectPropertyPolicy policy = new ObjectPropertyPolicy();
					PolicyType rightsProgramType = new PolicyType("HON4_RightsProgram");
					PolicyProperty property = new PolicyProperty();
					property.setModifier(PolicyProperty.WITH_PROPERTIES, true);
					rightsProgramType.addProperty(property);
					rightsProgramType.addProperty("object_type");
					rightsProgramType.addProperty("object_name");
					rightsProgramType.addProperty("hon4_RightsMembers");
					policy.addType(rightsProgramType);
					sessionService.setObjectPropertyPolicy(policy);
					
					for(int rnx=0; rnx<totalRightsProgram; rnx++) {
						if(honRightsProgram[rnx] instanceof WorkspaceObject) {
							dmService.getProperties(new ModelObject[] { honRightsProgram[rnx] }, new String[] {"object_type"});
							String objectType = honRightsProgram[rnx].getTypeObject().getName();
							System.out.println("objectType : "+ objectType);
							if(objectType.compareTo("HON4_RightsProgram") == 0) {
								dmService.getProperties(new ModelObject[] { honRightsProgram[rnx] }, new String[] {"object_name", "hon4_RightsMembers"});
								
								String programName = honRightsProgram[rnx].getPropertyObject("object_name").getStringValue();
								System.out.println("programName : "+ programName);
								
								//Check the updated program in AECS PRM exists in Teamcenter
								if(programName.compareTo(aecsPRMName) == 0) {
									String[] programMembers = honRightsProgram[rnx].getPropertyObject("hon4_RightsMembers").getStringArrayValue();
									System.out.println("programMembers size : "+ programMembers.length);
									for(String member : programMembers) {
										System.out.println("member : "+ member);
									} 
									
									List<String> activeRightMembers = new ArrayList<String>();
									programRightMemberMap.replace(aecsPRMName, programMembers);
									
									for(int mnx=0; mnx < programMembers.length; mnx++) {
										String targetMember = programMembers[mnx];
//										if(targetMember.compareTo("h558556")==0)
//											continue;
										
										boolean isActive = false;
										isActive = Arrays.stream(programRightMemberMap.get(aecsPRMName))
					                      .anyMatch(member -> member == targetMember);
										
										if(isActive)
											activeRightMembers.add(targetMember);
									}
									
									//activeRightMembers.add("h558556");
									//activeRightMembers.remove("h558556");
									System.out.println("Active right members : "+ activeRightMembers.size());
									
									//Frame input for setProperties
									NameValueStruct1 propStruct = new NameValueStruct1();
									propStruct.name = "hon4_RightsMembers";
									propStruct.values = activeRightMembers.toArray(new String[0]);
									
									NameValueStruct1[] nameValueStructArray = new NameValueStruct1[1];
									nameValueStructArray[0] = propStruct;
									
									PropInfo info = new PropInfo();
									info.object = honRightsProgram[rnx];
									info.vecNameVal = nameValueStructArray;
									
									PropInfo[] propInfos = new PropInfo[1];
									propInfos[0] = info;
									
									SetPropertyResponse  setPropRes = null;
									setPropRes = dmService.setProperties(propInfos, new String[] {});
									if(setPropRes == null || setPropRes.data.sizeOfPartialErrors()>0) {
										StringBuilder sb = new StringBuilder();
										for(int enx=0; enx < setPropRes.data.sizeOfPartialErrors(); enx++) {
											sb.append(setPropRes.data.getPartialError(enx));
											sb.append("\n");
										}
										
										result = sb.toString();
										
									}else {
										result = "Successfully updated the rights program : " + programName;
									}
									
									break;
								}
							}
						}
					}
				}
				
				System.out.println("result : " + result);
				return result.trim();
			}
		}  catch (FileNotFoundException e) {
			return "ERROR: Your Input file is missing! \n "+e.getMessage();
		} catch (NullPointerException e) {
			return "ERROR: Input parameter are missing in properties file! \n "+e.getMessage();
		} catch (IOException e) {
			return "ERROR: Unable to open this file \n "+e.getMessage();
		} catch (ArrayIndexOutOfBoundsException e) {
			return "ERROR: Serverhost pair is not matching with userpasswordpair please check the contain of HON_TCuserLists.txt file \n ";
		}
		catch (Exception e) {
			return "ERROR: Some Exception occurred please check input values \n " + e.getMessage();
		}
	}

	public String getRightsProgramInTC() {
		String result = "";
		String LocalPath = "";
		String OsName = "";
		String serverHost = null;
		String userID = "";
		String userPassword = "";
		String queryName = "";
		
		ImanQuery query = null;
		
		StringBuilder failurls = new StringBuilder();
		StringBuilder successurls = new StringBuilder();
		boolean anySuccess = false;
		
		JSONObject prmObject = new JSONObject();
		
		try {
			// getting system ENV
			//LocalPath = System.getenv(Constants.getTcAecsHomeValue());
			LocalPath = "D:\\SPLM\\TC14\\TC_ROOT\\TC_AECS_HOME";
			System.out.println("LocalPath : " + LocalPath);
			
			OsName = System.getProperty(Constants.getOSNameValue());
			System.out.println("OsName : "+ OsName);

			InputStream inputStream = null;
			Properties properties = new Properties();
			
			if (OsName.contains("Win")) {
				inputStream = new FileInputStream(LocalPath + "\\HON_Login_Details.properties");
			} else {
				inputStream = new FileInputStream(LocalPath + "/HON_Login_Details.properties");
			}
			properties.load(inputStream);
			
			List<String> requiredFileds=Arrays.asList("SERVERHOST","USER_ID","USER_PASS","QUERY");
			StringBuilder errors=new StringBuilder();
			
			for(String filed:requiredFileds)
			{
				String value=properties.getProperty(filed);
				if(value==null)
				{
					errors.append(filed).append(" is Missing\n");
				}else if(value.trim().isEmpty())
				{
					errors.append(filed).append(" is Empty\n");
				}
			}
			
			System.out.println("Errors Length : " + errors.length());
			
			if(errors.length()>0)
			{
				return errors.toString();
			}
			
			serverHost = properties.getProperty("SERVERHOST");
			userID = properties.getProperty("USER_ID");
			userPassword = properties.getProperty("USER_PASS");

			AppXSession session = new AppXSession(serverHost);
			String loginUser = "";
			loginUser = session.login(userID, userPassword);

			if (loginUser.equals("null")) {
				failurls.append(serverHost).append("\n");
			} else {
				successurls.append(serverHost).append("\n");
				anySuccess = true;
			}
			

			if (!anySuccess) {
				String res = "\nConnection is failed for following Site:\n" + failurls.toString().trim();
				return res.toString().trim();
			} else if (failurls.length() > 0) {
				return "\nPartial Success.\nScuccessful Site(s):" + successurls.toString().trim() + "\nFailed Site(s):"
						+ failurls.toString().trim();
			} else {
				DataManagementService dmService = DataManagementService.getService(AppXSession.getConnection());
				SavedQueryService queryService = SavedQueryService.getService(AppXSession.getConnection());
				SessionService sessionService = SessionService.getService(AppXSession.getConnection());
				
				queryName = properties.getProperty("QUERY");
				FindSavedQueriesCriteriaInput[] input = new FindSavedQueriesCriteriaInput[1];
				input[0] = new FindSavedQueriesCriteriaInput();
				input[0].queryNames = new String[] { queryName };
				FindSavedQueriesResponse response = queryService.findSavedQueries(input);
				if (response != null && response.savedQueries.length == 1) 
				{
					query = response.savedQueries[0];
				} else 
				{
					result = "General... query not found, please contact sys admin.";		
					return result;
				}
				
				SavedQueryInput savedQueryInput[] = new SavedQueryInput[1];
				savedQueryInput[0] = new SavedQueryInput();
				
				savedQueryInput[0].query = query; 
				savedQueryInput[0].entries = new String[] {"Type" }; 
				savedQueryInput[0].values = new String[] { "Rights Program" };
				
				ExecuteSavedQueriesResponse executeSavedQueryResponse = queryService.executeSavedQueries(savedQueryInput);
				if (executeSavedQueryResponse.serviceData.sizeOfPartialErrors() > 0) 
				{
					int errorCount = executeSavedQueryResponse.serviceData.sizeOfPartialErrors();
					System.out.println("ExecuteSavedQueriesResponse error count : " + errorCount);
					for(int enx=0; enx < errorCount; enx++) {
						result += executeSavedQueryResponse.serviceData.getPartialError(enx);
					}
					System.out.println("result : "+ result);
					return result.trim();
				} 
				else 
				{
					SavedQueryResults found = executeSavedQueryResponse.arrayOfResults[0];
					ModelObject honRightsProgram[] = found.objects;
					int totalRightsProgram=honRightsProgram.length;
					System.out.println("\n Total Rights Program found: " + totalRightsProgram);
					
					ObjectPropertyPolicy policy = new ObjectPropertyPolicy();
					PolicyType rightsProgramType = new PolicyType("HON4_RightsProgram");
					PolicyProperty property = new PolicyProperty();
					property.setModifier(PolicyProperty.WITH_PROPERTIES, true);
					rightsProgramType.addProperty(property);
					rightsProgramType.addProperty("object_type");
					rightsProgramType.addProperty("object_name");
					rightsProgramType.addProperty("hon4_RightsMembers");
					policy.addType(rightsProgramType);
					sessionService.setObjectPropertyPolicy(policy);
					
					for(int rnx=0; rnx<totalRightsProgram; rnx++) {
						if(honRightsProgram[rnx] instanceof WorkspaceObject) {
							dmService.getProperties(new ModelObject[] { honRightsProgram[rnx] }, new String[] {"object_type"});
							String objectType = honRightsProgram[rnx].getTypeObject().getName();
							System.out.println("objectType : "+ objectType);
							if(objectType.compareTo("HON4_RightsProgram") == 0) {
								dmService.getProperties(new ModelObject[] { honRightsProgram[rnx] }, new String[] {"object_name", "hon4_RightsMembers"});
								
								String programName = honRightsProgram[rnx].getPropertyObject("object_name").getStringValue();
								System.out.println("programName : "+ programName);
								
								String[] programMembers = honRightsProgram[rnx].getPropertyObject("hon4_RightsMembers").getStringArrayValue();
								System.out.println("programMembers size : "+ programMembers.length);
								for(String member : programMembers) {
									System.out.println("member : "+ member);
								} 
								
								//Frame JSON object
								prmObject.put(programName, programMembers);
						
							}
						}
					}
				}
				
				System.out.println("result : " + prmObject.toString(4));
				return prmObject.toString(4).trim();
			}
		}  catch (FileNotFoundException e) {
			return "ERROR: Your Input file is missing! \n "+e.getMessage();
		} catch (NullPointerException e) {
			return "ERROR: Input parameter are missing in properties file! \n "+e.getMessage();
		} catch (IOException e) {
			return "ERROR: Unable to open this file \n "+e.getMessage();
		} catch (ArrayIndexOutOfBoundsException e) {
			return "ERROR: Serverhost pair is not matching with userpasswordpair please check the contain of HON_TCuserLists.txt file \n ";
		}
		catch (Exception e) {
			return "ERROR: Some Exception occurred please check input values \n " + e.getMessage();
		}
		
	}

}
