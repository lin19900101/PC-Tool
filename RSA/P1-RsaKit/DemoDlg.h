#include "BigInt.h"

class CDemoDlg : public CDialog
{
public:
	CDemoDlg(CWnd* pParent = NULL);   // standard constructor

	//{{AFX_DATA(CDemoDlg)
	enum { IDD = IDD_DEMO_FORM };
	CString	m_D;
	CString	m_E;
	CString	m_N;
	CString	m_IN;
	CString	m_OUT;
	int		m_Len;
	//}}AFX_DATA

	CBigInt P,Q,N,D,E;
	int seed,ready;

protected:
	//{{AFX_VIRTUAL(CDemoDlg)
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

	//{{AFX_MSG(CDemoDlg)
	afx_msg void OnClickDecrypt();
	afx_msg void OnClickEncrypt();
	afx_msg void OnButtonGet();
	afx_msg void OnButtonPut();
	DECLARE_EVENTSINK_MAP()
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};
