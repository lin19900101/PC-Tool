#include "stdafx.h"
#include "RsaKit.h"
#include "ToolDlg.h"

CToolDlg::CToolDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CToolDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CToolDlg)
	m_A = _T("");
	m_B = _T("");
	m_C = _T("");
	//}}AFX_DATA_INIT
}

void CToolDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CToolDlg)
	DDX_Text(pDX, IDC_A, m_A);
	DDX_Text(pDX, IDC_B, m_B);
	DDX_Text(pDX, IDC_C, m_C);
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CToolDlg, CDialog)
	//{{AFX_MSG_MAP(CToolDlg)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


BEGIN_EVENTSINK_MAP(CToolDlg, CDialog)
    //{{AFX_EVENTSINK_MAP(CToolDlg)
	ON_EVENT(CToolDlg, IDC_ADD, -600 /* Click */, OnClickAdd, VTS_NONE)
	ON_EVENT(CToolDlg, IDC_DEC, -600 /* Click */, OnClickDec, VTS_NONE)
	ON_EVENT(CToolDlg, IDC_DIV, -600 /* Click */, OnClickDiv, VTS_NONE)
	ON_EVENT(CToolDlg, IDC_EUC, -600 /* Click */, OnClickEuc, VTS_NONE)
	ON_EVENT(CToolDlg, IDC_HEX, -600 /* Click */, OnClickHex, VTS_NONE)
	ON_EVENT(CToolDlg, IDC_MOD, -600 /* Click */, OnClickMod, VTS_NONE)
	ON_EVENT(CToolDlg, IDC_MUL, -600 /* Click */, OnClickMul, VTS_NONE)
	ON_EVENT(CToolDlg, IDC_SUB, -600 /* Click */, OnClickSub, VTS_NONE)
	//}}AFX_EVENTSINK_MAP
END_EVENTSINK_MAP()

void CToolDlg::OnClickAdd() 
{
    UpdateData(TRUE);
	if((m_A.GetLength()>310)||(m_B.GetLength()>310))
	{
		m_C=_T("A、B不得大于310位");
		UpdateData(FALSE);
		return;
	}
	for(int i=0;i<m_A.GetLength();i++)
	{
		if((m_A[i]<'0')||(m_A[i]>'9'))
		{
			m_C=_T("A必须为0-9组成的整数");
			UpdateData(FALSE);
			return;
		}
	}
    A.Get(m_A,DEC);
	B.Get(m_B,DEC);
	C.Mov(A.Add(B));
	C.Put(m_C,DEC);
	UpdateData(FALSE);
    return;
}

void CToolDlg::OnClickSub() 
{
    UpdateData(TRUE);
	if((m_A.GetLength()>310)||(m_B.GetLength()>310))
	{
		m_C=_T("A、B不得大于310位");
		UpdateData(FALSE);
		return;
	}
	for(int i=0;i<m_A.GetLength();i++)
	{
		if((m_A[i]<'0')||(m_A[i]>'9'))
		{
			m_C=_T("A必须为0-9组成的整数");
			UpdateData(FALSE);
			return;
		}
	}
	A.Get(m_A,DEC);
	B.Get(m_B,DEC);
	if(A.Cmp(B)>=0)
	{
		C.Mov(A.Sub(B));
		C.Put(m_C,DEC);
	}
	else
	{
		C.Mov(B.Sub(A));
		C.Put(m_C,DEC);
		m_C.Insert(0,'-');
	}
	UpdateData(FALSE);
    return;
}

void CToolDlg::OnClickMul() 
{
    UpdateData(TRUE);
	if((m_A.GetLength()+m_B.GetLength())>310)
	{
		m_C=_T("A、B位数之和不得大于310");
		UpdateData(FALSE);
		return;
	}
	for(int i=0;i<m_A.GetLength();i++)
	{
		if((m_A[i]<'0')||(m_A[i]>'9'))
		{
			m_C=_T("A必须为0-9组成的整数");
			UpdateData(FALSE);
			return;
		}
	}
	A.Get(m_A,DEC);
	B.Get(m_B,DEC);	
	C.Mov(A.Mul(B));
	C.Put(m_C,DEC);
	UpdateData(FALSE);
    return;
}

void CToolDlg::OnClickDiv() 
{
    UpdateData(TRUE);
	if((m_A.GetLength()>310)||(m_B.GetLength()>310))
	{
		m_C=_T("A、B不得大于310位");
		UpdateData(FALSE);
		return;
	}
	for(int i=0;i<m_A.GetLength();i++)
	{
		if((m_A[i]<'0')||(m_A[i]>'9'))
		{
			m_C=_T("A必须为0-9组成的整数");
			UpdateData(FALSE);
			return;
		}
	}
	if((m_B=="0")||(m_B==""))
	{
		m_C=_T("B不得为0");
		UpdateData(FALSE);
		return; 
	}
	A.Get(m_A,DEC);
	B.Get(m_B,DEC);	
	C.Mov(A.Div(B));
	C.Put(m_C,DEC);
	UpdateData(FALSE);
    return;
}

void CToolDlg::OnClickMod() 
{
    UpdateData(TRUE);
	if((m_A.GetLength()>310)||(m_B.GetLength()>310))
	{
		m_C=_T("A、B不得大于310位");
		UpdateData(FALSE);
		return;
	}
	for(int i=0;i<m_A.GetLength();i++)
	{
		if((m_A[i]<'0')||(m_A[i]>'9'))
		{
			m_C=_T("A必须为0-9组成的整数");
			UpdateData(FALSE);
			return;
		}
	}
	if((m_B=="0")||(m_B==""))
	{
		m_C=_T("B不得为0");
		UpdateData(FALSE);
		return; 
	}
	A.Get(m_A,DEC);
	B.Get(m_B,DEC);	
	C.Mov(A.Mod(B));
	C.Put(m_C,DEC);
	UpdateData(FALSE);
    return;	
}

void CToolDlg::OnClickEuc() 
{
    UpdateData(TRUE);
	if((m_A.GetLength()>310)||(m_B.GetLength()>310))
	{
		m_C=_T("A、B不得大于310位");
		UpdateData(FALSE);
		return;
	}
	for(int i=0;i<m_A.GetLength();i++)
	{
		if((m_A[i]<'0')||(m_A[i]>'9'))
		{
			m_C=_T("A必须为0-9组成的整数");
			UpdateData(FALSE);
			return;
		}
	}
	A.Get(m_A,DEC);
	B.Get(m_B,DEC);	
	if(A.Cmp(B)<=0)
	{
		m_C=_T("B必须小于A");
		UpdateData(FALSE);
		return;
	}
	C.Mov(B.Euc(A));
	C.Put(m_C,DEC);
	UpdateData(FALSE);
    return;	
}

void CToolDlg::OnClickHex() 
{
    UpdateData(TRUE);
	if(m_A.GetLength()>310)
	{
		m_C=_T("A不得大于310位");
		UpdateData(FALSE);
		return;
	}
	for(int i=0;i<m_A.GetLength();i++)
	{
		if((m_A[i]<'0')||(m_A[i]>'9'))
		{
			m_C=_T("A必须为0-9组成的整数");
			UpdateData(FALSE);
			return;
		}
	}
	A.Get(m_A,DEC);
	A.Put(m_C,HEX);
	UpdateData(FALSE);
    return;	
}

void CToolDlg::OnClickDec() 
{
    UpdateData(TRUE);
	if(m_A.GetLength()>256)
	{
		m_C=_T("A不得大于256位");
		UpdateData(FALSE);
		return;
	}
	for(int i=0;i<m_A.GetLength();i++)
	{
		if((m_A[i]<'0')||
		   ((m_A[i]>'9')&&(m_A[i]<'A'))||
		   ((m_A[i]>'F')&&(m_A[i]<'a'))||
		   (m_A[i]>'f'))
		{
			m_C=_T("A必须为0-9或A-F或a-f组成的整数");
			UpdateData(FALSE);
			return;
		}
	}
	A.Get(m_A,HEX);
	A.Put(m_C,DEC);
	UpdateData(FALSE);
    return;		
}
