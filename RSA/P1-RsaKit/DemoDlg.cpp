#include "stdafx.h"
#include "RsaKit.h"
#include "DemoDlg.h"
#include "Str2Hex.cpp"

CDemoDlg::CDemoDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CDemoDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CDemoDlg)
	m_D = _T("");
	m_E = _T("");
	m_N = _T("");
	m_IN = _T("");
	m_OUT = _T("");
	m_Len = 0;
	ready = 0;
	//}}AFX_DATA_INIT
	CTime t = CTime::GetCurrentTime();
    seed=t.GetSecond();
    srand(seed);
}

void CDemoDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CDemoDlg)
	DDX_Text(pDX, IDC_D, m_D);
	DDX_Text(pDX, IDC_E, m_E);
	DDX_Text(pDX, IDC_N, m_N);
	DDX_Text(pDX, IDC_INPUT, m_IN);
	DDX_Text(pDX, IDC_OUTPUT, m_OUT);
	DDX_CBIndex(pDX, IDC_COMBO, m_Len);
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CDemoDlg, CDialog)
	//{{AFX_MSG_MAP(CDemoDlg)
	ON_BN_CLICKED(IDC_BUTTON_GET, OnButtonGet)
	ON_BN_CLICKED(IDC_BUTTON_PUT, OnButtonPut)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

BEGIN_EVENTSINK_MAP(CDemoDlg, CDialog)
    //{{AFX_EVENTSINK_MAP(CDemoDlg)
	ON_EVENT(CDemoDlg, IDC_DECRYPT, -600 /* Click */, OnClickDecrypt, VTS_NONE)
	ON_EVENT(CDemoDlg, IDC_ENCRYPT, -600 /* Click */, OnClickEncrypt, VTS_NONE)
	//}}AFX_EVENTSINK_MAP
END_EVENTSINK_MAP()

void CDemoDlg::OnButtonPut() 
{
	UpdateData(TRUE);
	ready=0;
	if(m_N.GetLength()>256)
	{
		m_OUT=_T("N不得大于256位");
		UpdateData(FALSE);
		return;
	}
	if(m_E.GetLength()>256)
	{
		m_OUT=_T("E不得大于256位");
		UpdateData(FALSE);
		return;
	}
    if(m_D.GetLength()>10)
	{
		m_OUT=_T("N不得大于10位");
		UpdateData(FALSE);
		return;
	}

	for(int i=0;i<m_N.GetLength();i++)
	{
		if((m_N[i]<'0')||
		   ((m_N[i]>'9')&&(m_N[i]<'A'))||
		   ((m_N[i]>'F')&&(m_N[i]<'a'))||
		   (m_N[i]>'f'))
		{
			m_OUT=_T("N必须为0-9或A-F或a-f组成的整数");
			UpdateData(FALSE);
			return;
		}
	}
	for(i=0;i<m_E.GetLength();i++)
	{
		if((m_E[i]<'0')||
		   ((m_E[i]>'9')&&(m_E[i]<'A'))||
		   ((m_E[i]>'F')&&(m_E[i]<'a'))||
		   (m_E[i]>'f'))
		{
			m_OUT=_T("E必须为0-9或A-F或a-f组成的整数");
			UpdateData(FALSE);
			return;
		}
	}
	for(i=0;i<m_D.GetLength();i++)
	{
		if((m_D[i]<'0')||
		   ((m_D[i]>'9')&&(m_D[i]<'A'))||
		   ((m_D[i]>'F')&&(m_D[i]<'a'))||
		   (m_D[i]>'f'))
		{
			m_OUT=_T("D必须为0-9或A-F或a-f组成的整数");
			UpdateData(FALSE);
			return;
		}
	}
	N.Get(m_N);
	D.Get(m_D);
	E.Get(m_E);
	if((N.Cmp(E)<=0)||(N.Cmp(D)<=0))
	{
		m_OUT=_T("N必须大于D、E");
		UpdateData(FALSE);
		return;
	}
	ready=1;
	Q.m_ulValue[0]=0;
}

void CDemoDlg::OnButtonGet() 
{
	ready=1;
	UpdateData(TRUE);
	int len=2;
	for(int i=0;i<m_Len;i++){len*=2;}
    CTime t0=CTime::GetCurrentTime();
	P.Mov(0);
	Q.Mov(0);
	N.Mov(0);
	E.Mov(0);
	P.GetPrime(len);
	Q.GetPrime(len);
	N.Mov(P.Mul(Q));
	N.Put(m_N);
	P.m_ulValue[0]--;
	Q.m_ulValue[0]--;
	P.Mov(P.Mul(Q));
	D.Mov(0x10001);
	m_D="10001";
	E.Mov(D.Euc(P));
	E.Put(m_E);
    CTime t1=CTime::GetCurrentTime();
    CTimeSpan t=t1-t0;
	m_OUT.Format("%d",t.GetTotalSeconds());
	m_OUT+=" 秒";
	Q.m_ulValue[0]=0;
	UpdateData(FALSE);
}

void CDemoDlg::OnClickEncrypt() 
{

	if(ready==0)
	{
		m_OUT=_T("请先输入或生成N、D、E");
        UpdateData(FALSE);
		return;
	}
	UpdateData(TRUE);
    if(m_IN.GetLength()>256)
	{
		m_OUT=_T("N不得大于256位");
		UpdateData(FALSE);
		return;
	}
	int i=0,len=0,j=0;
	/*
	for(int i=0;i<m_IN.GetLength();i++)
	{
		if((m_IN[i]<'0')||
		   ((m_IN[i]>'9')&&(m_IN[i]<'A'))||
		   ((m_IN[i]>'F')&&(m_IN[i]<'a'))||
		   (m_IN[i]>'f'))
		{
			m_OUT=_T("待加密数据必须为0-9或A-F或a-f组成的整数");
			UpdateData(FALSE);
			return;
		}
	}	*/
    _TCHAR *pHex;
	

    len= 1+sizeof( _TCHAR )*m_IN.GetLength();//加一才能除掉字符串打印尾巴


	pHex=(char*)malloc(2*len);//BI_MAXLEN=35
	if( !pHex )
	{
		m_OUT=_T("无法为pHex分配足够内存");
        UpdateData(FALSE);

		return;
	}
    memset(pHex, '\0', 2*len );

    
    //如："yaolixing"->"79616F6C6978696E67"
	Str2Hex(IN  m_IN,IN len, OUT  pHex);

    
	CString s=pHex;

	P.Get(s);
	
	//频繁从堆中分配内存，降低了效率，但我也没有办法:<
	free(pHex);


	if(P.Cmp(N)>=0)
	{
		m_OUT=_T("待加密数据必须小于N");
        UpdateData(FALSE);
		return;
	}

	Q.Mov(P.RsaTrans(E,N));//明文P被私钥{E，N}加密后，传给Q
	Q.Put(m_OUT);//密文Q被显示出来
	//显示修改后的 
	UpdateData(FALSE);

}

void CDemoDlg::OnClickDecrypt() 
{
	
	_TCHAR* Str=0;
	int   pHexLen=0;

	if((ready==0)||(Q.m_ulValue[0]==0))
	{
		m_OUT=_T("请先进行加密");
        UpdateData(FALSE);
		return;
	}


	Q.Get(m_OUT);
	P.Mov(Q.RsaTrans(D,N));
	P.Put(m_OUT);
	//改变m_OUT的输出显示，即将"79616F6C6978696E67"显示为“yaolixing”
    pHexLen= sizeof( _TCHAR )*m_OUT.GetLength()+1;
    
	//因为pHexLen>sizeof(_TCHAR)*m_OUT.GetLength()，
	//所以pHexLen/2在做向下取整动作时
	//不会造成内存越界访问错误。
	Str = (char*)malloc(pHexLen<<1);

	if(!Str)
	{
	   m_OUT=_T("不能为pHexLen分配内存\n");
	   UpdateData(FALSE);
	   return;
	}
    
	memset(Str, '\0', pHexLen<<1);

	//"79616F6C6978696E67"->"yaolixing"
	Hex2Str( IN     m_OUT,
             IN     pHexLen,    
             OUT    Str
              );

	MessageBox(Str,0,MB_OK);

	strncpy(m_OUT.GetBuffer(m_OUT.GetLength()), Str, pHexLen<<1);

	UpdateData(FALSE);
}
