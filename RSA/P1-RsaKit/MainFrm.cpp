#include "stdafx.h"
#include "RsaKit.h"
#include "MainFrm.h"
#include "ToolDlg.h"
#include "DemoDlg.h"
#include "HelpDlg.h"

IMPLEMENT_DYNAMIC(CMainFrame, CFrameWnd)

BEGIN_MESSAGE_MAP(CMainFrame, CFrameWnd)
	//{{AFX_MSG_MAP(CMainFrame)
	ON_WM_CREATE()
	ON_COMMAND(ID_DEMO, OnDemo)
	ON_COMMAND(ID_HELP, OnHelp)
	ON_COMMAND(ID_TOOL, OnTool)
	ON_WM_GETMINMAXINFO()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

static UINT indicators[] =
{
	ID_SEPARATOR,           // status line indicator
};

int CMainFrame::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if (CFrameWnd::OnCreate(lpCreateStruct) == -1)
		return -1;
    m_wndToolBar.CreateEx(this, TBSTYLE_FLAT, WS_VISIBLE | CBRS_FLYBY | CBRS_TOP);
	m_wndToolBar.LoadToolBar(IDR_MAINFRAME);

	m_wndStatusBar.Create(this);
	m_wndStatusBar.SetIndicators(indicators, sizeof(indicators)/sizeof(UINT));

	m_pDlg = new CToolDlg;
	m_pDlg->Create(IDD_TOOL_FORM,this);
	m_pDlg->MoveWindow(0,40,629,383);
	m_pDlg->ShowWindow(SW_SHOW);
	return 0;
}

BOOL CMainFrame::PreCreateWindow(CREATESTRUCT& cs)
{
	cs.style = WS_OVERLAPPED | WS_CAPTION | FWS_ADDTOTITLE
		| WS_THICKFRAME | WS_SYSMENU;
	cs.dwExStyle &= ~WS_EX_CLIENTEDGE;
	cs.lpszClass = AfxRegisterWndClass(0);
	cs.cx = 640;
	cs.cy = 480;
	return CFrameWnd::PreCreateWindow(cs);
}

void CMainFrame::OnGetMinMaxInfo(MINMAXINFO FAR* lpMMI) 
{
    lpMMI->ptMinTrackSize.x = 640;
	lpMMI->ptMaxTrackSize.x = 640;
    lpMMI->ptMinTrackSize.y = 480;
	lpMMI->ptMaxTrackSize.y = 480;	
	CFrameWnd::OnGetMinMaxInfo(lpMMI);
}

void CMainFrame::OnTool() 
{
	delete m_pDlg;
	m_pDlg = new CToolDlg;
	m_pDlg->Create(IDD_TOOL_FORM,this);
	m_pDlg->MoveWindow(0,40,629,383);
	m_pDlg->ShowWindow(SW_SHOW);	
}

void CMainFrame::OnDemo() 
{
	delete m_pDlg;
	m_pDlg = new CDemoDlg;
	m_pDlg->Create(IDD_DEMO_FORM,this);
	m_pDlg->MoveWindow(0,40,629,383);
	m_pDlg->ShowWindow(SW_SHOW);	
}

void CMainFrame::OnHelp() 
{
	delete m_pDlg;
	m_pDlg = new CHelpDlg;
	m_pDlg->Create(IDD_HELP_FORM,this);
	m_pDlg->MoveWindow(0,40,629,383);
	m_pDlg->ShowWindow(SW_SHOW);
}
