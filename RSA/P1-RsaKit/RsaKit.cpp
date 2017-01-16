#include "stdafx.h"
#include "RsaKit.h"
#include "MainFrm.h"

BEGIN_MESSAGE_MAP(CRsaKitApp, CWinApp)
	//{{AFX_MSG_MAP(CRsaKitApp)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

CRsaKitApp theApp;

BOOL CRsaKitApp::InitInstance()
{
	AfxEnableControlContainer();
	Enable3dControls();
	CMainFrame* pFrame = new CMainFrame;
	m_pMainWnd = pFrame;
	pFrame->Create(NULL,_T("RsaKit_V1.0 by afanty"));
	pFrame->EnableToolTips();
	pFrame->ShowWindow(SW_SHOW);
	pFrame->UpdateWindow();
	return TRUE;
}
