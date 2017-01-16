class CHelpDlg : public CDialog
{
public:
	CHelpDlg(CWnd* pParent = NULL);   // standard constructor

	//{{AFX_DATA(CHelpDlg)
	enum { IDD = IDD_HELP_FORM };
	CEdit	    m_Edit;
	CTreeCtrl	m_Tree;
	//}}AFX_DATA

	CString     m_Text;

protected:
	//{{AFX_VIRTUAL(CHelpDlg)
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

	//{{AFX_MSG(CHelpDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSelchangedTree(NMHDR* pNMHDR, LRESULT* pResult);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};
