class CMainFrame : public CFrameWnd
{
protected: 
	DECLARE_DYNAMIC(CMainFrame)

	//{{AFX_VIRTUAL(CMainFrame)
	public:
	virtual BOOL PreCreateWindow(CREATESTRUCT& cs);
	//}}AFX_VIRTUAL

	CStatusBar  m_wndStatusBar;
	CToolBar    m_wndToolBar;
	CDialog*    m_pDlg;

	//{{AFX_MSG(CMainFrame)
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg void OnDemo();
	afx_msg void OnHelp();
	afx_msg void OnTool();
	afx_msg void OnGetMinMaxInfo(MINMAXINFO FAR* lpMMI);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};
