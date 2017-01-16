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
		m_OUT=_T("N���ô���256λ");
		UpdateData(FALSE);
		return;
	}
	if(m_E.GetLength()>256)
	{
		m_OUT=_T("E���ô���256λ");
		UpdateData(FALSE);
		return;
	}
    if(m_D.GetLength()>10)
	{
		m_OUT=_T("N���ô���10λ");
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
			m_OUT=_T("N����Ϊ0-9��A-F��a-f��ɵ�����");
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
			m_OUT=_T("E����Ϊ0-9��A-F��a-f��ɵ�����");
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
			m_OUT=_T("D����Ϊ0-9��A-F��a-f��ɵ�����");
			UpdateData(FALSE);
			return;
		}
	}
	N.Get(m_N);
	D.Get(m_D);
	E.Get(m_E);
	if((N.Cmp(E)<=0)||(N.Cmp(D)<=0))
	{
		m_OUT=_T("N�������D��E");
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
	m_OUT+=" ��";
	Q.m_ulValue[0]=0;
	UpdateData(FALSE);
}

void CDemoDlg::OnClickEncrypt() 
{

	if(ready==0)
	{
		m_OUT=_T("�������������N��D��E");
        UpdateData(FALSE);
		return;
	}
	UpdateData(TRUE);
    if(m_IN.GetLength()>256)
	{
		m_OUT=_T("N���ô���256λ");
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
			m_OUT=_T("���������ݱ���Ϊ0-9��A-F��a-f��ɵ�����");
			UpdateData(FALSE);
			return;
		}
	}	*/
    _TCHAR *pHex;
	

    len= 1+sizeof( _TCHAR )*m_IN.GetLength();//��һ���ܳ����ַ�����ӡβ��


	pHex=(char*)malloc(2*len);//BI_MAXLEN=35
	if( !pHex )
	{
		m_OUT=_T("�޷�ΪpHex�����㹻�ڴ�");
        UpdateData(FALSE);

		return;
	}
    memset(pHex, '\0', 2*len );

    
    //�磺"yaolixing"->"79616F6C6978696E67"
	Str2Hex(IN  m_IN,IN len, OUT  pHex);

    
	CString s=pHex;

	P.Get(s);
	
	//Ƶ���Ӷ��з����ڴ棬������Ч�ʣ�����Ҳû�а취:<
	free(pHex);


	if(P.Cmp(N)>=0)
	{
		m_OUT=_T("���������ݱ���С��N");
        UpdateData(FALSE);
		return;
	}

	Q.Mov(P.RsaTrans(E,N));//����P��˽Կ{E��N}���ܺ󣬴���Q
	Q.Put(m_OUT);//����Q����ʾ����
	//��ʾ�޸ĺ�� 
	UpdateData(FALSE);

}

void CDemoDlg::OnClickDecrypt() 
{
	
	_TCHAR* Str=0;
	int   pHexLen=0;

	if((ready==0)||(Q.m_ulValue[0]==0))
	{
		m_OUT=_T("���Ƚ��м���");
        UpdateData(FALSE);
		return;
	}


	Q.Get(m_OUT);
	P.Mov(Q.RsaTrans(D,N));
	P.Put(m_OUT);
	//�ı�m_OUT�������ʾ������"79616F6C6978696E67"��ʾΪ��yaolixing��
    pHexLen= sizeof( _TCHAR )*m_OUT.GetLength()+1;
    
	//��ΪpHexLen>sizeof(_TCHAR)*m_OUT.GetLength()��
	//����pHexLen/2��������ȡ������ʱ
	//��������ڴ�Խ����ʴ���
	Str = (char*)malloc(pHexLen<<1);

	if(!Str)
	{
	   m_OUT=_T("����ΪpHexLen�����ڴ�\n");
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
