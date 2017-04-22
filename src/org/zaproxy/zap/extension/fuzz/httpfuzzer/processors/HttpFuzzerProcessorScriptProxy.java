package org.zaproxy.zap.extension.fuzz.httpfuzzer.processors;

import java.util.Map;
import javax.script.ScriptException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzResult;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerTaskProcessorUtils;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class HttpFuzzerProcessorScriptProxy implements HttpFuzzerProcessorScriptWithParameters {

	public final static String TYPE_NAME = "httpfuzzerprocessor";
	private static final Logger log = Logger.getLogger(HttpFuzzerProcessorScriptProxy.class);
	HttpFuzzerProcessorScript script;
	HttpFuzzerProcessorScriptWithParameters scriptWithParameters;
	
	public static HttpFuzzerProcessorScriptProxy create(ScriptWrapper scriptWrapper) throws Exception{
		HttpFuzzerProcessorScriptProxy proxy = new HttpFuzzerProcessorScriptProxy();
		ExtensionScript extensionScript = Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extensionScript != null) {
        	
            try{
            	proxy.scriptWithParameters = extensionScript.getInterface(scriptWrapper, HttpFuzzerProcessorScriptWithParameters.class);
            	return proxy;
            }catch(Exception e){
            	logNotImplementedInterface(scriptWrapper, HttpFuzzerProcessorScriptWithParameters.class, e);
            }           
        	
        	try {
        		proxy.script = extensionScript.getInterface(scriptWrapper, HttpFuzzerProcessorScript.class);
        		return proxy;
            } catch (Exception e) {
            	logNotImplementedInterface(scriptWrapper, HttpFuzzerProcessorScript.class, e);
            	throw e;
            }
        }
        return null;
	}

	private static <T> void logNotImplementedInterface(ScriptWrapper scriptWrapper, Class<T> classType, Exception e) {
		if (log.isDebugEnabled()) {
			log.debug("Script '" + scriptWrapper.getName() + "' does not implement the expected interface (" + classType.getSimpleName() + ")." , e);
		}
	}
	
	@Override
	public void processMessage(HttpFuzzerTaskProcessorUtils utils, HttpMessage message, Map<String, String> paramsValues) throws ScriptException {
		if(scriptWithParameters != null){
			scriptWithParameters.processMessage(utils, message, paramsValues);
			return;
		}
		else if(script != null){
			script.processMessage(utils, message);
			return;
		}
	}

	@Override
	public boolean processResult(HttpFuzzerTaskProcessorUtils utils, HttpFuzzResult result,	Map<String, String> paramsValues) throws ScriptException {
		if(scriptWithParameters != null){
			return scriptWithParameters.processResult(utils, result, paramsValues);			
		}
		else if(script != null){
			return script.processResult(utils, result);
		}
		return true;
	}

	@Override
	public String[] getRequiredParamsNames() {
		if(scriptWithParameters != null){
			return scriptWithParameters.getRequiredParamsNames();
		}		
		return new String[0];
	}

	@Override
	public String[] getOptionalParamsNames() {
		if(scriptWithParameters != null){
			return scriptWithParameters.getOptionalParamsNames();
		}		
		return new String[0];
	}
}
