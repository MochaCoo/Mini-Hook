#pragma once
#include <stdio.h>
#include <Windows.h>
#include "LDasm.h"
//�����:����HOOK�����ַʱ���ڴ�������HOOK Bridge�Ŀռ��˷�,����ʱ�ƺ�����΢�������
//https://www.cnblogs.com/luconsole/p/14813573.html
//�̰߳�ȫ:���ú����HOOKʱ,�ڸ���hook��ʱ����ͣ��ǰ������ ����ǰ�߳�������������̣߳��ټ���ִ�и���hook���߼�������hook���֮���ж����������̵߳�eip������ִ�еĴ����ַ���Ƿ�ΪĿ�꺯����ǰ�������ǵ��ֽڣ�����ǣ���Ҫ��eip�������õ����庯����Ӧ��λ�á���������������������̡߳�

class miniHook
{
private:
	void* HookAddr;//��Hook��ַ,ֻ�޸��׵�ַ5�ֽ�
	unsigned int len;//��Hook�ֽ���
	void* HookFunc;//����Hook����
	void* Bridge;//x86: ԭ����ԭ����ָ�� + jmp  x64: Callԭ��������: [(ԭ����ԭ����ָ�� + jmp)] + [far jmp(HOOK ������ת)]
#ifdef _WIN64
	void* AllocAt(void* Addr, size_t l);//��ָ����ַ����+-2GB������һ���ڴ�
#endif
public:
	~miniHook();
	miniHook();
	miniHook(void* Addr, void* NewFunc, BOOL Start = true);
	void* Set(void* Addr, void* NewFunc
		, BOOL Start = true//�Ƿ�������ʼHook
	);//�����µĺ�����ַ
	BOOL Start();//Hookԭ����ǰ5�ֽ�
	BOOL Stop();//��ԭԭ����ǰ5�ֽ�
	void* GetBridge();
};