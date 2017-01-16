#include "BigInt.h"

class CToolDlg : public CDialog
{
public:
	CToolDlg(CWnd* pParent = NULL);   // standard constructor

	//{{AFX_DATA(CToolDlg)
	enum { IDD = IDD_TOOL_FORM };
	CString	m_A;
	CString	m_B;
	CString	m_C;
	//}}AFX_DATA

	CBigInt A,B,C;

protected:
	//{{AFX_VIRTUAL(CToolDlg)
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

	//{{AFX_MSG(CToolDlg)
	afx_msg void OnClickAdd();
	afx_msg void OnClickDec();
	afx_msg void OnClickDiv();
	afx_msg void OnClickEuc();
	afx_msg void OnClickHex();
	afx_msg void OnClickMod();
	afx_msg void OnClickMul();
	afx_msg void OnClickSub();
	DECLARE_EVENTSINK_MAP()
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};
